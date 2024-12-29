from client.client import Client


def main():
    client = Client()
    client.set_up_communication()
    client.generate_one_time_keys()
    client.start_communication()


if __name__ == '__main__':
    main()
