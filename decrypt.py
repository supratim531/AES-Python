import os
import rsa
import sys

from colored import fg, attr


program_files = ["decrypt.py", "encrypt.py"]
valid_extension = ["c", "js", "md", "py", "ts",
                   "cpp", "css", "txt", "html", "java", "json"]


def failure_message(text):
    print(fg("red") + "FAILED: " + text + attr("reset"))


def success_message(text):
    print(fg("green") + "SUCCESS: " + text + attr("reset"))


def load_secret_key(file_name):
    private_key = None

    try:
        with open(f".\\keys\\{file_name}.secret.key", "rb") as f_ptr:
            private_key = (rsa.PrivateKey.load_pkcs1(
                f_ptr.read().decode('utf8')))

    except FileNotFoundError:
        return 404

    except:
        return None

    return private_key


def check_file(file_name=""):
    if not os.path.isfile(file_name):
        return False, False

    if len(file_name.split('.')) != 2 or file_name.split('.')[1] not in valid_extension:
        return True, False

    return True, True


def file_exist_and_valid(file_name=""):
    if file_name in program_files:
        print("DecryptionError: access is denied.")
        return False

    elif os.path.isdir(file_name):
        print("DecryptionError: access is denied.")
        return False

    exist, valid = check_file(file_name)

    if not exist:
        failure_message(f"{file_name} does not exist in this directory.")
        return False

    elif not valid:
        failure_message(
            f"{file_name} does not support this decryption due to the extension.")
        return False

    return True


def __decrypt_file__(file):
    content, old_content, old_bin_content = None, None, None

    try:
        with open(file, "r") as f_ptr:
            old_content = f_ptr.read()

    except:
        pass

    try:
        if file_exist_and_valid(file_name=file):
            private_key = load_secret_key(file_name=file)

            if private_key == None:
                failure_message(
                    f"signature of keys/{file}.secret.key is not valid.")
                return

            elif private_key == 404:
                failure_message(
                    f"secret key of {file} is missing from keys directory.")
                return

            with open(file, "rb") as f_ptr:
                old_bin_content = f_ptr.read()

            with open(file, "rb") as f_ptr1:
                content = f_ptr1.read()

                with open(file, "w") as f_ptr2:
                    f_ptr2.write(rsa.decrypt(content, private_key).decode())
                    success_message(f"{file} is decrypted successfully.")

    except:
        mode, content = ("wb", old_bin_content) if old_bin_content is not None else (
            "w", old_content)

        with open(file, mode) as f_ptr:
            f_ptr.write(content)

        failure_message(f"{file} cannot be decrypted.")


def decrypt(*args):
    if type(args[0]) != type([]):
        file = args[0]
        __decrypt_file__(file=file)

    else:
        for file in args[0]:
            __decrypt_file__(file=file)


def __decrypt__(resource):
    decrypt(resource)


def __main__(argv=[]):
    if len(argv) == 1:
        print("DecryptionError: no such file(s) specified.")

    elif not os.path.isdir("keys"):
        print(
            "DecryptionError: directory of name [keys] is not found at present location for decryption.")

    elif argv[1] == '*':
        for file in os.listdir():
            if os.path.isfile(file) and file not in program_files:
                __decrypt__(resource=file)

    else:
        for i in range(1, len(argv)):
            file = argv[i]
            __decrypt__(resource=file)


if __name__ == "__main__":
    __main__(sys.argv)
