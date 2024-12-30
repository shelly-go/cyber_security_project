from client.client import Client


def main():
    client = Client()
    client.set_up_communication()
    client.generate_one_time_keys()
    client.send_message("12345", "Secret Tunnel!")


if __name__ == '__main__':
    main()
