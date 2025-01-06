import threading
import time

from client.client import Client
from client.consts import STARTUP_BANNER, MSG_RECEIVE_THREAD_TIMEOUT, MSG_RECEIVE_RATE


def main():
    print(STARTUP_BANNER)

    offline_mode = False
    debug_mode = False

    phone_num = input("Enter your phone number: ")
    client = Client(phone_num)
    client.set_up_communication()

    def message_receiver():
        while True:
            if not offline_mode:
                client.receive_messages()
            time.sleep(MSG_RECEIVE_RATE)

    receiver_thread = threading.Thread(target=message_receiver, daemon=True)
    receiver_thread.start()

    while True:
        if offline_mode:
            print("You are offline. Please go online or exit.")
            choice = input("Enter 'online' to go back online or 'exit' to quit: ").strip().lower()
            if choice == 'online':
                offline_mode = False
                print("You are back online.")
            elif choice == 'exit':
                break
            continue

        print(f"\nOptions:\n1. Send a message\n2. Go offline\n3. Turn debug mode {'off' if debug_mode else 'on'}")
        print("Type 'exit' to Exit\n")
        choice = input("Choose an option (1/2/3/4): \n").strip()

        if choice == '1':
            target = input("Enter the target phone number: ")
            message = input("Enter the message: ")
            if not target.isdigit():
                print("Target must be a phone number!")
                continue
            client.send_message(target, message)
        elif choice == '2':
            offline_mode = True
            print("You are now offline.")
        elif choice == '3':
            debug_mode = not debug_mode
            client.set_logger_level_debug(debug_mode)
        elif choice.lower() == 'exit':
            break
    receiver_thread.join(MSG_RECEIVE_THREAD_TIMEOUT)


if __name__ == "__main__":
    main()
