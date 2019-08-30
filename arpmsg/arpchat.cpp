#include <stdio.h>
#include <unistd.h>
#include <sys/select.h>

#include <iostream>
#include <string>

using namespace std;

int main(int, char**) {
    string message_text;

    while (true) {
        fd_set fds_set;
        FD_ZERO(&fds_set);
        FD_SET(STDIN_FILENO, &fds_set);

        // wait for either a packet or user input
        if (select(STDIN_FILENO + 1, &fds_set, nullptr, nullptr, nullptr) < 0) {
            cerr << "Error selecting." << endl;
            return 64;
        };

        // collect part of the message
        string message_text_part;
        getline(cin, message_text_part);
        message_text += message_text_part;

        cout << message_text;
    }
}


