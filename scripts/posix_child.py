"""Fresh-process controlling-TTY setup avoids preexec_fn in a threaded manager."""
import fcntl
import os
import sys
import termios

if __name__ == '__main__':
    descriptor = int(sys.argv[1])
    fcntl.ioctl(descriptor, termios.TIOCSCTTY, 0)
    os.close(descriptor)
    os.execvp(sys.argv[2], sys.argv[2:])
