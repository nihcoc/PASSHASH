import mysql.connector
from datetime import datetime
db=mysql.connector.connect(host="localhost",user="root",password="1332",database="password_manager")
cursor=db.cursor()

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

H = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
]


def right_rotate(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xffffffff


def hash_pswd(key_in):

    # Convert text to bytes
    key_in = bytearray(key_in.encode())

    # Original length in bits
    bit_length = len(key_in) * 8

    # Append a 1 bit
    key_in.append(0x80)

    # Pad until length is 448 mod 512
    while (len(key_in) * 8) % 512 != 448:
        key_in.append(0)

    # Append original length as 64-bit big-endian
    key_in += bit_length.to_bytes(8, "big")

    h = H.copy()

    # Process each 512-bit block
    for chunk_start in range(0, len(key_in), 64):

        chunk = key_in[chunk_start:chunk_start + 64]

        # key_in schedule
        w = []

        for i in range(16):
            word = int.from_bytes(
                chunk[i * 4:i * 4 + 4],
                "big"
            )
            w.append(word)

        for i in range(16, 64):

            s0 = (
                right_rotate(w[i - 15], 7)
                ^ right_rotate(w[i - 15], 18)
                ^ (w[i - 15] >> 3)
            )

            s1 = (
                right_rotate(w[i - 2], 17)
                ^ right_rotate(w[i - 2], 19)
                ^ (w[i - 2] >> 10)
            )

            w.append(
                (w[i - 16] + s0 + w[i - 7] + s1)
                & 0xffffffff
            )

        # Working variables
        a, b, c, d, e, f, g, h = h

        # 64 compression rounds
        for i in range(64):

            S1 = (
                right_rotate(e, 6)
                ^ right_rotate(e, 11)
                ^ right_rotate(e, 25)
            )

            ch = (e & f) ^ (~e & g)

            temp1 = (
                h + S1 + ch + K[i] + w[i]
            ) & 0xffffffff

            S0 = (
                right_rotate(a, 2)
                ^ right_rotate(a, 13)
                ^ right_rotate(a, 22)
            )

            maj = (a & b) ^ (a & c) ^ (b & c)

            temp2 = (S0 + maj) & 0xffffffff

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xffffffff

        # Add result to hash state
        h_values = [a, b, c, d, e, f, g, h]

        for i in range(8):
            h[i] = (h[i] + h_values[i]) & 0xffffffff

    # Convert eight 32-bit words into 256-bit hex string
    return ''.join(f'{x:08x}' for x in h)


def encrypt(psw, key):
    result = ""

    for char in psw:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shifted = (ord(char) - base + key) % 26
            result += chr(base + shifted)
        else:
            result += char

    return result


def decrypt(psw, key):
    return encrypt(psw, -key)



def record_activity(username,action):
    file=open("activity_log.txt","a")
    time=datetime.now()
    file.write(str(time)+"|"+username+"|"+action+"\n")
    file.close()

def create_account():
    username=input("Enter user ID: ")
    query=("select username from users where username='{}'").format(username)
    cursor.execute(query)
    result=cursor.fetchone()
    if result is not None:
        print("User ID already exists.")
    else:
        new_key=input("Enter password: ")
        stored_hash=hash_pswd(new_key)
        query2=("insert into users (username,password_hash) values ('{}','{}')").format(username,stored_hash)
        cursor.execute(query2)
        db.commit()
        record_activity(username,"Account created")
        print("Account created successfully.")
        
def login():
    global result
    username=input("Enter user ID: ")
    query=("select username from users where username='{}'").format(username)
    cursor.execute(query)
    result=cursor.fetchone()
    if result is None:
        print("User ID not found.")
        record_activity(username,"Unsuccessful login")
    else:
        attempts_left=3
        while attempts_left>0:
            psd_login=input("Enter password: ")
            if hash_pswd(psd_login)==result[1]:
                print("Logged in successfully.")
                record_activity(username,"Successful login")
                user_menu(username)
                break
            else:
                attempts_left-=1
                print("Incorrect password.")
                record_activity(username,"Unsuccessful login")
                if attempts_left>0:
                    print("Attempts left:", attempts_left)
                else:
                    print("Too many incorrect attempts.")      
        
def user_menu(username):
    while True:
        print("===== USER MENU =====")
        print("1. Search for a saved password")
        print("2. View all saved passwords")
        print("3. Add a password")
        print("4. Modify a saved password")
        print("5. Delete a saved password")
        print("6. Modify account password")
        print("7. Delete account")
        print("8. Log out")
        choice=int(input("Enter choice: "))
        if choice==1:
            search_password(username)
        elif choice==2:
            view_passwords(username)
        elif choice==3:
            add_password(username)
        elif choice==4:
            modify_saved_password(username)
        elif choice==5:
            delete_saved_password(username)
        elif choice==6:
            modify_account_password(username)
        elif choice==7:
            delete_account(username)
        elif choice==8:
            print("Logged out successfully.")
            break
        else:
            print("Invalid choice.")
            
def search_password(username):
    app_name=input("Enter app name: ")
    query=("select app_name,username,encrypted_password from passwords where username='{}' and app_name='{}'").format(username,app_name)
    cursor.execute(query)
    result=cursor.fetchone()
    if result is None:
        print("No saved password.")
    else:
            app_name=result[0]
            username=result[1]
            password=decrypt(result[2])
            print("App:",app_name)
            print("Username:",username)
            print("Password:",password)
            
def view_passwords(username):
    query=("select app_name,username,encrypted_password from passwords where username='{}'").format(username)
    cursor.execute(query)
    results=cursor.fetchall()
    if results==[]:
        print("No saved passwords.")
    else:
        for result in results:
            app_name=result[0]
            username=result[1]
            password=decrypt(result[2])
            print("App:",app_name)
            print("Username:",username)
            print("Password:",password)
            
def add_password(username):
    app_name=input("Enter app name: ")
    query1=("select app_name from passwords where username='{}' and app_name='{}'").format(username,app_name)
    cursor.execute(query1)
    result=cursor.fetchone()
    if result is not None:
        print("Password already exists")
    else:
        username=input("Enter username: ")
        password=input("Enter password: ")
        encrypted_password=encrypt(password)
        query2=("insert into passwords (username,app_name,username,encrypted_password) values ('{}','{}','{}','{}')").format(username,app_name,username,encrypted_password)
        cursor.execute(query2)
        db.commit()
        record_activity(username,"Password added: "+app_name)
        print("Password added successfully.")
            
def modify_saved_password(username):
    app_name=input("Enter app name: ")
    query1=("select app_name,username,encrypted_password from passwords where username='{}' and app_name='{}'").format(username,app_name)
    cursor.execute(query1)
    result=cursor.fetchone()
    if result is None:
        print("No saved password.")
    else:
        new_password=input("Enter new password: ")
        confirm_password=input("Confirm new password: ")
        if new_password!=confirm_password:
            print("Passwords do not match.")
        else:
            new_encrypted_password=encrypt(new_password)
            query2=("update passwords set encrypted_password='{}' where username='{}' and app_name='{}'").format(new_encrypted_password,username,app_name)
            cursor.execute(query2)
            db.commit()
            record_activity(username,"Password modified: "+app_name)
            print("Password modified successfully.")
            
def delete_saved_password(username):
    app_name=input("Enter app name: ")
    query1=("select app_name from passwords where username='{}' and app_name='{}'").format(username,app_name)
    cursor.execute(query1)
    result=cursor.fetchone()
    if result is None:
        print("No saved password.")
    else:
        confirmation=input("Confirm deletion (yes/no): ")
        if confirmation.lower()=="yes":
            query2=("delete from passwords where username='{}' and app_name='{}'").format(username,app_name)
            cursor.execute(query2)
            db.commit()
            record_activity(username,"Password deleted: "+app_name)
            print("Password deleted successfully.")
        else:
            print("Password deletion cancelled.")

def modify_account_password(username):
    password=input("Enter current password: ")
    if hash_pswd(password)==result[1]:
        new_password=input("Enter new password: ")
        confirm_password=input("Confirm new password: ")
        if new_password!=confirm_password:
            print("Passwords do not match.")
        else:
            new_hash=hash_pswd(new_password)
            query=("update users set password_hash='{}' where username='{}'").format(new_hash,username)
            cursor.execute(query)
            db.commit()
            record_activity(username,"Account password modified")  
            print("Password modified successfully.")      
    else:
        print("Incorrect password.")

def delete_account(username):
    password=input("Enter password: ")
    if hash_pswd(password)==result[1]:
        confirmation=input("Confirm deletion (yes/no): ")
        if confirmation.lower()=="yes":
            query1=("delete from users where username='{}'").format(username)
            query2=("delete from passwords where username='{}'").format(username)
            cursor.execute(query1)
            cursor.execute(query2)
            db.commit()
            record_activity(username,"Account deleted")
            print("Account deleted successfully.")
        else:
            print("Account deletion cancelled.")
    else:
        print("Incorrect password.")

while True:
    print("===== PASSWORD MANAGER =====")
    print("1. Login")
    print("2. Create account")
    print("3. Exit")
    choice=int(input("Enter choice: "))
    if choice==1:
        login()
    elif choice==2:
        create_account()
    elif choice==3:
        print("Thank you for using the password manager.")
        break
    else:
        print("Invalid choice.")

cursor.close()
db.close()