import os
import secrets
import string
import subprocess
import sys
import shutil
import grp

from gvm.transforms import EtreeCheckCommandTransform
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.errors import GvmError

from ptlibs.app_dirs import AppDirs

class GVMSetup:
    
    PASSWORD_FILE = os.path.join(AppDirs("ptopenvas").get_base_dir(), "gvm.pass")
    
    def __init__(self, args={}) -> None:    
        self.args = args

    def run(self) -> bool:
        """
        Main function to ensure dependencies and GVM setup.
        Returns True if everything is ready.
        """
        # 1. Install GVM and ensure initialization
        self.install_gvm() # ensure gvm is installed
        self.ensure_gvmd_initialized() # run gvm-setup

        # 2. Ensure GVMD service is running
        self.run_gvmd_daemon()

        # 3. Finalize permissions
        self.finalize_permissions()
        
        # 4. Ensure penterep user exists (creates with random password if needed)
        self.ensure_penterep_user()

        return True
    
    def install_gvm(self) -> bool:
        """
        Verifies if the 'gvm' package is installed.
        Installs it if missing.
        """

        # Check installation state
        try:
            subprocess.run(
                ["dpkg", "-s", "gvm"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True
            )
            print("Package 'gvm' is already installed.")
            return True

        except subprocess.CalledProcessError:
            print("Package 'gvm' is missing. Installing...")
            try:
                subprocess.run(["sudo", "apt", "update"], check=True)
                subprocess.run(["sudo", "apt", "install", "-y", "gvm"], check=True)
                print("Package 'gvm' installed successfully.")
                return True

            except subprocess.CalledProcessError as e:
                print(f"Failed to install 'gvm': {e}")
                return False

    def ensure_gvmd_initialized(self) -> bool:
        """
        Ensure GVMD is initialized by running `gvm-setup` if needed.

        This checks for the GVMD Unix socket at `/run/gvmd/gvmd.sock` and
        runs `gvm-setup` only when initialization appears required.
        """
        # 1) Check if GVMD database exists
        try:
            db_check = subprocess.run(
                ["sudo", "-u", "postgres", "psql", "-tAc", "SELECT 1 FROM pg_database WHERE datname='gvmd'"],
                #["-u", "postgres", "psql", "-tAc", "SELECT 1 FROM pg_database WHERE datname='gvmd'"],
                capture_output=True, text=True, check=True
            )
            if db_check.stdout.strip() == "1":
                #print("GVM setup was already completed previously.")
                return True
        except Exception:
            pass

        # If database missing -> setup never ran
        try:
            print("Running gvm-setup...")
            subprocess.run(["sudo", "gvm-setup"], check=True)
            print("GVMD initialization completed successfully.")
            return True
        except subprocess.CalledProcessError as e:
            print(f"GVMD initialization failed: {e}")
            return False

    def run_gvmd_daemon(self):
        """
        Ensure that the GVMD service is running. 
        Starts it if it is not active.
        """
        try:
            #status = subprocess.run(["systemctl", "is-active", "--quiet", "gvmd"])
            status = subprocess.run(["systemctl", "is-active", "--quiet", "gvmd"])
            if status.returncode != 0:
                print("GVMD service is not running. Starting with gvm-start...")
                subprocess.run(["sudo", "gvm-start"], check=True)
                print("GVM stack started.")
            else:
                pass
                #print("GVMD service is already running.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to start GVMD service: {e}")

    def ensure_penterep_user(self):
        """
        Ensure gvmd service is running and the 'penterep' admin user exists.
        If the user does not exist, create it with a random password stored in PASSWORD_FILE.
        If the provided admin password is wrong, it will be reset automatically.
        """

        # 1. Define admin username and get password
        USERNAME = "penterep"
        PASSWORD = self.get_password() # "admin"

        self._create_user_if_needed(username=USERNAME, password=PASSWORD)

        # 2. Determine password for penterep
        if not PASSWORD:
            alphabet = string.ascii_letters + string.digits
            PASSWORD = ''.join(secrets.choice(alphabet) for _ in range(24))
            with open(self.PASSWORD_FILE, "w") as f:
                f.write(PASSWORD)

        # 3. Connect to gvmd and create user if missing
        conn = UnixSocketConnection(path="/run/gvmd/gvmd.sock")
        try:
            with Gmp(conn, transform=EtreeCheckCommandTransform()) as gmp:
                try:
                    gmp.authenticate(USERNAME, PASSWORD)
                except GvmError as e:
                    try:
                        subprocess.run([
                            "sudo", "-u", "_gvm", "gvmd",
                            "--user=penterep",
                            f"--new-password={PASSWORD}"
                        ], check=True, capture_output=True)
                        #print(f"Reset penterep password to '{PASSWORD}'")
                    except Exception as e:
                        print(f"Failed to reset penterep password: {e}")
                        return

        except PermissionError:
            print("Please reset your shell (log out and log back in) before running scripts that access GVMD.")
        except GvmError as e:
            print(f"Failed to create user: {e}")

    def _create_user_if_needed(self, username, password):
        r = subprocess.run([
            "sudo", "-u", "_gvm", "gvmd",
            "--get-users"
            ], check=True, capture_output=True)

        available_users = [u for u in r.stdout.decode().split("\n") if u]
        #print("Available_users:\n   ", '\n    '.join(available_users))

        if username not in available_users:
            try:
                # Create admin user
                subprocess.run([
                    "sudo", "-u", "_gvm", "gvmd",
                    "--create-user="+username,
                    "--password="+password,
                ], check=True, capture_output=True)
                print(f"Created admin user '{username}' with password '{password}'")
            except Exception as e:
                print(f"Failed to create user '{username}': {e}")
                return


    def get_password(self, generate: bool = False) -> str:
        """
        Return the stored password from PASSWORD_FILE.
        If the file is missing or empty, or generate=True, create a new password, save it, and return it.
        """
        def generate_password() -> str:
            charset = string.ascii_letters + string.digits
            new_pass = ''.join(secrets.choice(charset) for _ in range(32))
            with open(self.PASSWORD_FILE, "w") as f:
                f.write(new_pass)
            return new_pass

        # Generate a new password if requested or if the file is missing/empty
        if generate or not os.path.exists(self.PASSWORD_FILE):
            return generate_password()

        # Read existing password
        with open(self.PASSWORD_FILE, "r") as f:
            existing_pass = f.read().strip()

        # If file is empty, generate a new password
        if not existing_pass:
            return generate_password()

        return existing_pass


    def finalize_permissions(self):
        """
        Add the current user to the _gvm group so the Python script can access the GVMD socket.
        The user must reset their shell for the group change to take effect.
        """
        user = os.environ.get("USER")
        if not user:
            print("Could not determine the current user.")
            return

        # Check membership
        try:
            group = grp.getgrnam("_gvm")
        except KeyError:
            print("Group '_gvm' does not exist.")
            return
        
        if user in group.gr_mem:
            #print(f"User '{user}' is already a member of the _gvm group. No action taken.")
            return

        try:
            subprocess.run(["sudo", "usermod", "-aG", "_gvm", user], check=True)
            print(f"User '{user}' has been added to the _gvm group.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to add user to _gvm group: {e}")


if __name__ == "__main__":
    gvm = GVMSetup(args={})
    gvm.run()