#include <bits/stdc++.h>

int main(int argc, char *argv[]) {

	/*
	 * Note, cmd line arg is not called with ./<program> < <input>
	 */
	std::cout << "Checking cmdline arguments\n";
	std::cout << "argc: " << argc << std::endl;
	for(int i = 0; i < argc; i++) {
		std::cout << "argv[" << i << "]: " << argv[i] << std::endl;
	}

	/*
	 * Checking stdinput
	 */
	std::cout << "Checking stdinput\n";
	std::string line;
	while(std::getline(std::cin, line)) {
		std::cout << line << std::endl;
	}

	return 0;
}
