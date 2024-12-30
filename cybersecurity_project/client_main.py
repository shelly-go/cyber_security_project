from client.client import Client


def main():
    client = Client()
    client.set_up_communication()
    client.generate_one_time_keys()
    client.get_target_id_key("12345")


if __name__ == '__main__':
    main()
