import sys


class UsernameProvider:
    """Fetch username from operating system.

    getpass is not used on linux because it does not return the
    correct username when using `su` command with `-c` option.

    Howerver, using getuid + getpwuid seems to work in all cases.

    Example of wrong behaviour using `getpass`:

    ```bash
    su -c "python3 -c 'import getpass; print(getpass.getuser())'" root
    ```

    print current username instead of printing `root`.
    """

    def __init__(self) -> None:
        """Load platform dependant modules required to identify username"""
        if "linux" in sys.platform:
            from os import getuid
            from pwd import getpwuid

            def get_user() -> str:
                """Get user name even if user is not logged in an interactive session"""
                username = getpwuid(getuid()).pw_name
                return username

        else:
            from getpass import getuser

            def get_user() -> str:
                username = getuser()
                return username

        self.get_user = get_user
