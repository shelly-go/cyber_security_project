from client.client import Client


def main():
    client = Client()
    client.set_up_communication()
    client.generate_one_time_keys()
    target = "12345"
    message = "Well hello there"
    client.send_message(target, message+"1")
    client.send_message(target, message+"2")
    client.send_message(target, message+"3")
    client.receive_messages()
    client.receive_messages()
    client.send_message(target, message+"4")


if __name__ == '__main__':
    main()
