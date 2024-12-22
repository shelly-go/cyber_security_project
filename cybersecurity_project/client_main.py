from client.client import Client


def main():
    client = Client()
    client.set_up_communication()
    client.start_communication()


if __name__ == '__main__':
    main()
