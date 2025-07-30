import os
import getpass
import time
from authentication import UserManager
from encryption import MessageManager

def main():
    user_manager = UserManager()
    message_manager = MessageManager(user_manager)
    
    current_user = None
    private_key = None
    
    while True:
        if current_user is None:
            print("\n===== Secure Messaging App =====")
            print("1. Login")
            print("2. Register")
            print("3. Exit")
            choice = input("Enter your choice (1-3): ")
            
            if choice == "1":
                username = input("Username: ")
                password = getpass.getpass("Password: ")
                success, result = user_manager.authenticate_user(username, password)
                if success:
                    current_user = username
                    private_key = result
                    print(f"Logged in as {current_user}")
                else:
                    print(f"Login failed: {result}")
            elif choice == "2":
                username = input("Username: ")
                password = getpass.getpass("Password: ")
                password_confirm = getpass.getpass("Confirm Password: ")
                
                if not username:
                    print("Username cannot be empty")
                    continue
                if not password or not password_confirm:
                    print("Password and confirmation cannot be empty")
                    continue
                if password != password_confirm:
                    print("Passwords do not match")
                    continue
                
                success, result = user_manager.register_user(username, password)
                if success:
                    print(result)
                else:
                    print(f"Registration failed: {result}")
            elif choice == "3":
                break
            else:
                print("Invalid choice")
        else:  # User is logged in
            print(f"\n===== Logged in as {current_user} =====")
            print("1. Send Message")
            print("2. View Messages")
            print("3. Logout")
            print("4. Exit")
            print("5. Revoke User")
            choice = input("Enter your choice (1-5): ")
            
            if choice == "1":
                recipient = input("Recipient username: ")
                message = input("Message: ")
                success, result = message_manager.encrypt_message(current_user, recipient, message)
                if success:
                    print(f"Message sent with ID: {result}")
                else:
                    print(f"Failed to send message: {result}")
            elif choice == "2":
                message_files = [f for f in os.listdir("messages") if f.endswith(".json")]
                if not message_files:
                    print("No messages found")
                    continue
                
                available_messages = []
                for msg_file in message_files:
                    with open(os.path.join("messages", msg_file), 'r') as f:
                        import json
                        msg_data = json.load(f)
                        if msg_data["recipient"] == current_user:
                            msg_id = msg_file.split(".")[0]
                            sender = msg_data["sender"]
                            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', 
                                                   time.localtime(msg_data["timestamp"]))
                            available_messages.append((msg_id, sender, timestamp))
                
                if not available_messages:
                    print("No messages for you")
                    continue
                
                print("\nYour Messages:")
                for i, (msg_id, sender, timestamp) in enumerate(available_messages, 1):
                    print(f"{i}. From: {sender}, Time: {timestamp}")
                
                msg_choice = input("Enter message number to read (or 0 to go back): ")
                try:
                    msg_idx = int(msg_choice) - 1
                    if msg_idx < 0:
                        continue
                    
                    msg_id = available_messages[msg_idx][0]
                    success, result = message_manager.decrypt_message(
                        current_user, msg_id, private_key
                    )
                    if success:
                        print(f"\nFrom: {available_messages[msg_idx][1]}")
                        print(f"Time: {available_messages[msg_idx][2]}")
                        print(f"Message: {result}")
                    else:
                        print(f"Failed to decrypt message: {result}")
                except (ValueError, IndexError):
                    print("Invalid selection")
            elif choice == "3":
                current_user = None
                private_key = None
                print("Logged out")
            elif choice == "4":
                break
            elif choice == "5":
                username_to_revoke = input("Enter username to revoke: ")
                user_manager.revoke_user(username_to_revoke)
                print(f"User {username_to_revoke} revoked")
            else:
                print("Invalid choice")

if __name__ == "__main__":
    main()
