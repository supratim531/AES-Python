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


def dump_secret_key(file_name, private_key):
    if not os.path.isdir("keys"):
        os.mkdir("keys")

    with open(f".\\keys\\{file_name}.secret.key", "wb") as f_ptr:
        f_ptr.write(private_key.save_pkcs1())


def check_file(file_name=""):
    if not os.path.isfile(file_name):
        return False, False

    if len(file_name.split('.')) != 2 or file_name.split('.')[1] not in valid_extension:
        return True, False

    return True, True


def file_exist_and_valid(file_name=""):
    if file_name in program_files:
        print("EncryptionError: access is denied.")
        return False

    elif os.path.isdir(file_name):
        print("EncryptionError: access is denied.")
        return False

    exist, valid = check_file(file_name)

    if not exist:
        failure_message(f"{file_name} does not exist in this directory.")
        return False

    elif not valid:
        failure_message(
            f"{file_name} does not support this encryption due to the extension.")
        return False

    return True


def __encrypt_file__(file):
    if file_exist_and_valid(file_name=file):
        content = None

        with open(file, "r") as f_ptr:
            content = f_ptr.read()

        public_key, private_key = rsa.newkeys((os.path.getsize(file) + 11) * 8)

        with open(file, "wb") as f_ptr:
            f_ptr.write(rsa.encrypt(content.encode(), public_key))
            success_message(f"{file} is encrypted successfully.")

        dump_secret_key(file, private_key)


def encrypt(*args):
    if type(args[0]) != type([]):
        file = args[0]
        __encrypt_file__(file=file)

    else:
        for file in args[0]:
            __encrypt_file__(file=file)


def __encrypt__(resource):
    try:
        encrypt(resource)

    except UnicodeDecodeError:
        failure_message(f"{resource} cannot be encrypted.")


def __main__(argv=[]):
    if len(argv) == 1:
        print("EncryptionError: no such file(s) specified.")

    elif argv[1] == '*':
        for file in os.listdir():
            if os.path.isfile(file) and file not in program_files:
                __encrypt__(resource=file)

    else:
        for i in range(1, len(argv)):
            file = argv[i]
            __encrypt__(resource=file)

    print(fg("cyan") +
          f"\nNOTE: secret key of each encrypted files will be stored in the directory of name [keys]." + attr("reset"))


if __name__ == "__main__":
    __main__(sys.argv)
