#include "fuzzer.h"


int main(int argc, char* argv[]) {
	std::string program;
	if(argc != 2) {
		std::cout << "Usage: ./fuzzer <program>\n";
		exit(-1);
	}
	program = argv[1];

	// Set Working Directory
	if(chdir(fuzz::WORKING_DIR.c_str()) != 0) {
		std::cerr << "Error could not set working directory" << std::endl;
		return -1;
	}

	// Print Logo
	std::ifstream logo("util/logo");
	if(!logo) {
		std::cerr << "Error could not open logo file" << std::endl;
	}
	std::cout << logo.rdbuf();
	logo.close();

	// fuzz a program 
	fuzz::fuzz_file(program, 100);
	fuzz::print_statistics();

	/*
	std::string test = "mutate this";
	for(int i = 0; i < 100; i++) {
		fuzz::mutate_input(test, 32, 64);
	}
	*/

	return 0;
}

