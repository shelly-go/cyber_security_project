from client.client import Client


def main():
    client = Client()
    client.set_up_communication()
    client.generate_one_time_keys()
    target = "12345"
    message = "Well hello there"
    client.send_message(target, message)
    client.receive_messages()
    client.receive_messages()


if __name__ == '__main__':
    main()
