/* SPDX-License-Identifier: LGPL-2.1-or-later
 * HarnessyXO software Bluetooth controllers, using the upstream BlueZ emulator.
 * No host hardware, RF access or network listener is opened.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <termios.h>
#include <unistd.h>
#include "emulator/btdev.h"
#include "src/shared/mainloop.h"

#define HELPER_VERSION "harnessy-test-bt1"
#define CONTROLLERS 2
#define INPUT_LIMIT 65535
#define OUTPUT_LIMIT (256 * 1024)

struct controller {
    int fd, slave;
    unsigned int number;
    struct btdev *device;
    uint8_t input[INPUT_LIMIT], output[OUTPUT_LIMIT];
    size_t input_size, output_size;
};
static struct controller controllers[CONTROLLERS];
static bool failed;

static void failure(const char *reason)
{
    if (!failed)
        fprintf(stderr, "harnessy-test-bt: %s\n", reason);
    failed = true;
    mainloop_quit();
}

static bool update_events(struct controller *controller)
{
    uint32_t events = EPOLLIN;
    if (controller->output_size)
        events |= EPOLLOUT;
    if (mainloop_modify_fd(controller->fd, events) < 0) {
        failure("could not update the controller transport");
        return false;
    }
    return true;
}

static bool flush_output(struct controller *controller)
{
    while (controller->output_size) {
        ssize_t written = write(controller->fd, controller->output,
                               controller->output_size);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            failure("controller output failed");
            return false;
        }
        if (!written) {
            failure("controller output stopped");
            return false;
        }
        controller->output_size -= written;
        memmove(controller->output, controller->output + written,
                controller->output_size);
    }
    return update_events(controller);
}

static void send_packet(const struct iovec *iov, int count, void *user_data)
{
    struct controller *controller = user_data;
    int i;
    if (failed)
        return;
    for (i = 0; i < count; ++i) {
        if (iov[i].iov_len > OUTPUT_LIMIT - controller->output_size) {
            failure("controller output queue exceeded its limit");
            return;
        }
        memcpy(controller->output + controller->output_size,
                iov[i].iov_base, iov[i].iov_len);
        controller->output_size += iov[i].iov_len;
    }
    flush_output(controller);
}

/* H4 lengths are little-endian on every guest, including big-endian MIPS.
 * Accumulate split headers and payloads before handing a complete packet to
 * BlueZ; one read may also contain several complete frames.
 */
static bool process_input(struct controller *controller)
{
    while (controller->input_size) {
        size_t header, payload, length;
        const uint8_t *packet = controller->input;
        switch (packet[0]) {
        case 0x01: header = 4; break; /* HCI command */
        case 0x02: header = 5; break; /* ACL data */
        case 0x03: header = 4; break; /* SCO data */
        case 0x05: header = 5; break; /* ISO data */
        default:
            failure("unsupported packet type on controller transport");
            return false;
        }
        if (controller->input_size < header)
            return true;
        if (packet[0] == 0x01 || packet[0] == 0x03)
            payload = packet[3];
        else {
            payload = (size_t) packet[3] | ((size_t) packet[4] << 8);
            if (packet[0] == 0x05)
                payload &= 0x3fff;
        }
        length = header + payload;
        if (length > INPUT_LIMIT) {
            failure("controller input frame exceeded its limit");
            return false;
        }
        if (controller->input_size < length)
            return true;
        btdev_receive_h4(controller->device, packet, (uint16_t) length);
        if (failed)
            return false;
        controller->input_size -= length;
        memmove(controller->input, controller->input + length,
                controller->input_size);
    }
    return true;
}

static void controller_event(int fd, uint32_t events, void *user_data)
{
    struct controller *controller = user_data;
    if (events & (EPOLLERR | EPOLLHUP)) {
        failure("controller transport disconnected");
        return;
    }
    if ((events & EPOLLOUT) && !flush_output(controller))
        return;
    if (!(events & EPOLLIN))
        return;
    for (;;) {
        ssize_t length;
        if (controller->input_size == INPUT_LIMIT) {
            failure("controller input buffer exceeded its limit");
            return;
        }
        length = read(fd, controller->input + controller->input_size,
                      INPUT_LIMIT - controller->input_size);
        if (length < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            failure("controller input failed");
            return;
        }
        if (!length) {
            failure("controller input stopped");
            return;
        }
        controller->input_size += length;
        if (!process_input(controller))
            return;
    }
}

static void handle_signal(int signum, void *user_data)
{
    (void) signum;
    (void) user_data;
    mainloop_quit();
}

static bool make_controller(struct controller *controller, unsigned int number,
                            int directory)
{
    struct termios attributes;
    char path[128], name[16];
    controller->number = number;
    controller->fd = posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
    if (controller->fd < 0 || grantpt(controller->fd) < 0 ||
            unlockpt(controller->fd) < 0 ||
            ptsname_r(controller->fd, path, sizeof(path)) != 0)
        return false;
    /* Keep the slave open until btattach starts, so the master cannot get EIO.
     * The kernel HCI line discipline is installed by the supervised btattach.
     */
    controller->slave = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
    if (controller->slave < 0 || tcgetattr(controller->slave, &attributes) < 0)
        return false;
    cfmakeraw(&attributes);
    attributes.c_cflag |= CLOCAL | CREAD;
    attributes.c_cflag &= ~CRTSCTS;
    if (tcsetattr(controller->slave, TCSANOW, &attributes) < 0)
        return false;
    controller->device = btdev_create(BTDEV_TYPE_BREDRLE52,
                                      (uint16_t) (0x4858 + number));
    if (!controller->device)
        return false;
    if (mainloop_add_fd(controller->fd, EPOLLIN, controller_event,
                        controller, NULL) < 0)
        return false;
    btdev_set_send_handler(controller->device, send_packet, controller);
    snprintf(name, sizeof(name), "hci%u", number);
    unlinkat(directory, name, 0);
    if (symlinkat(path, directory, name) < 0)
        return false;
    return true;
}

int main(int argc, char **argv)
{
    const char *runtime = "/var/run/harnessy-test-bluetooth";
    struct stat state;
    int directory = -1, lock = -1, ready = -1, result = EXIT_FAILURE;
    bool owns_runtime = false;
    unsigned int i;
    if (argc == 2 && !strcmp(argv[1], "--version")) {
        puts(HELPER_VERSION);
        return EXIT_SUCCESS;
    }
    if (argc == 3 && !strcmp(argv[1], "--runtime"))
        runtime = argv[2];
    else if (argc != 1) {
        fprintf(stderr, "Usage: harnessy-test-bt [--runtime DIRECTORY|--version]\n");
        return EXIT_FAILURE;
    }
    if (runtime[0] != '/' || strchr(runtime, '\n') || strchr(runtime, '\r') ||
            strcmp(strrchr(runtime, '/') + 1, "harnessy-test-bluetooth")) {
        fprintf(stderr, "harnessy-test-bt: use an absolute runtime directory named harnessy-test-bluetooth\n");
        return EXIT_FAILURE;
    }
    for (i = 0; i < CONTROLLERS; ++i)
        controllers[i].fd = controllers[i].slave = -1;
    if (mkdir(runtime, 0700) < 0 && errno != EEXIST)
        goto done;
    directory = open(runtime, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0 || fstat(directory, &state) < 0 ||
            state.st_uid != geteuid() || fchmod(directory, 0700) < 0)
        goto done;
    lock = openat(directory, "lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (lock < 0 || fstat(lock, &state) < 0 || !S_ISREG(state.st_mode) ||
            state.st_uid != geteuid() || state.st_nlink != 1 ||
            flock(lock, LOCK_EX | LOCK_NB) < 0)
        goto done;
    owns_runtime = true;
    unlinkat(directory, "ready.json", 0);
    unlinkat(directory, "ready.tmp", 0);
    mainloop_init();
    for (i = 0; i < CONTROLLERS; ++i) {
        if (!make_controller(&controllers[i], i, directory)) {
            fprintf(stderr, "harnessy-test-bt: could not create a Bluetooth controller; check PTYs, AF_ALG and guest crypto modules\n");
            goto done;
        }
    }
    ready = openat(directory, "ready.tmp", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (ready < 0)
        goto done;
    {
        const uint8_t *first = btdev_get_bdaddr(controllers[0].device);
        const uint8_t *second = btdev_get_bdaddr(controllers[1].device);
        if (dprintf(ready, "{\"schema\":1,\"version\":\"" HELPER_VERSION "\",\"pid\":%ld,\"controllers\":2,\"addresses\":[\"%02X:%02X:%02X:%02X:%02X:%02X\",\"%02X:%02X:%02X:%02X:%02X:%02X\"],\"backend\":\"bluez_h4\",\"physical_rf\":false}\n", (long) getpid(),
                first[5], first[4], first[3], first[2], first[1], first[0],
                second[5], second[4], second[3], second[2], second[1], second[0]) < 0 || fsync(ready) < 0)
            goto done;
    }
    close(ready);
    ready = -1;
    if (renameat(directory, "ready.tmp", directory, "ready.json") < 0)
        goto done;
    puts("HX_BLUETOOTH_READY controllers=2 backend=bluez_h4");
    fflush(stdout);
    result = mainloop_run_with_signal(handle_signal, NULL);
    if (failed)
        result = EXIT_FAILURE;
done:
    if (result != EXIT_SUCCESS && !failed)
        fprintf(stderr, "harnessy-test-bt: initialization or event loop failed\n");
    if (ready >= 0)
        close(ready);
    for (i = 0; i < CONTROLLERS; ++i)
        btdev_destroy(controllers[i].device);
    for (i = 0; i < CONTROLLERS; ++i) {
        if (controllers[i].fd >= 0) {
            mainloop_remove_fd(controllers[i].fd);
            close(controllers[i].fd);
        }
        if (controllers[i].slave >= 0)
            close(controllers[i].slave);
        if (owns_runtime) {
            char name[16];
            snprintf(name, sizeof(name), "hci%u", i);
            unlinkat(directory, name, 0);
        }
    }
    if (owns_runtime) {
        unlinkat(directory, "ready.json", 0);
        unlinkat(directory, "ready.tmp", 0);
    }
    if (directory >= 0)
        close(directory);
    if (lock >= 0)
        close(lock);
    return result == EXIT_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
}
