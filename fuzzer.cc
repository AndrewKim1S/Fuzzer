#include <iostream>
#include <random>
#include <fstream>
#include <array>

/*
 * Generate a random input string
 * char_code_start & char_code_end are in ascii codes
 */
std::string generateRandInput(int min_size, int max_size, int char_code_start, int char_code_end) {
	static std::random_device rd;
	static std::mt19937 gen(rd());
	
	auto rand = [&](int a, int b){
		std::uniform_int_distribution<int> dist(a, b);
		return dist(gen);
	};
		
	std::string input;
	size_t size = rand(min_size, max_size);
	for(int i = 0; i < size; i++) {
		char c = static_cast<char>(rand(char_code_start, char_code_end));
		input += c;
	}
	return input;
}


/*
 * Generate random inputs and place them into a file
 */
bool setupInputFile(std::string filename) {
	std::ofstream file(filename);
	if(!file) {
		std::cerr << "Error opening file!\n";
		return false;
	}
	for(int i = 0; i < 10; i++) {
		auto a = generateRandInput(10,80,32,64);
		file << a;
		file << "\n";
	}
	file.close();
	return true;
}


/*
 * Invoke External Program
 */
bool invokeExternalProgram(std::string command) {
	FILE* pipe = popen(command.c_str(), "r");
	if(!pipe) { 
		std::cerr << "Error popen\n";
		return false;
	}

	std::array<char, 128> buffer;
	std::string result;
	while(fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
		result += buffer.data();
	}
	pclose(pipe);

	std::cout << result << std::endl;
	return true;
}


int main() {
	std::ifstream logo("logo", std::ios::in | std::ios::binary);
	std::cout << logo.rdbuf();
	logo.close();


	std::string program = "test";
	std::string input_filename = "input";

	// Testing fuzzing input
	setupInputFile(input_filename);
	std::cout << "---------- fuzzing input generation complete ----------\n";


	// Invoke External Program
	std::string command = "./" + program + " < " + input_filename;
	invokeExternalProgram(command);
	std::cout << "invoke external process complete\n";

	return 0;
}

