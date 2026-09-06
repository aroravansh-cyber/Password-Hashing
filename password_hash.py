import hashlib
import secrets
import string


def hash_password(password):
    password = password.encode()
    hashed = hashlib.sha256(password)
    return hashed.hexdigest()


def generate_password(length):
    characters = string.ascii_letters + string.digits + string.punctuation

    password = ""

    for i in range(length):
        password += secrets.choice(characters)

    return password


print("=" * 50)
print("        PASSWORD SECURITY TOOL")
print("=" * 50)

print("\n1. Hash Password")
print("2. Generate Password")
print("3. Verify Password")
print("4. Exit")

choice = input("\nEnter your choice: ")


if choice == "1":

    password = input("Enter your password: ")

    password_hash = hash_password(password)

    print("\nPassword Hash:")
    print(password_hash)


elif choice == "2":

    length = int(input("Enter password length: "))

    if length < 8:
        print("Password should be at least 8 characters.")

    else:
        password = generate_password(length)

        print("\nGenerated Password:")
        print(password)


elif choice == "3":

    password = input("Enter your password: ")
    stored_hash = input("Enter stored hash: ")

    password_hash = hash_password(password)

    if password_hash == stored_hash:
        print("\nPassword Verified!")

    else:
        print("\nWrong Password!")


elif choice == "4":

    print("Program closed.")


else:

    print("Invalid choice.")