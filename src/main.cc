#include "fuzzer.h"


void setBinaryConfigs(fuzz::BinaryConfig& configs, std::string& filename) {
	std::ifstream file(filename);
	std::string line;
	std::string section;

	while(std::getline(file, line)) {
		// Remove leading and trailing whitespace
		line.erase(line.begin(), std::find_if(line.begin(), line.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
		line.erase(std::find_if(line.rbegin(), line.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), line.end());

		// Skip comments
		if(line.empty() || line[0] == ';' || line[0] == '#') {
			continue;
		}
		if(line[0] == '[' && line[line.size()-1] == ']') {
			section = line.substr(1, line.size()-2);
		}
		else {
			size_t equalPos = line.find('=');
			if(equalPos == std::string::npos) {
				continue; 
			}
			std::string key = line.substr(0, equalPos-1);
			std::string value = line.substr(equalPos+1);

			key.erase(0, key.find_first_not_of(" \t"));
			key.erase(key.find_last_not_of(" \t") + 1);
			value.erase(0, value.find_first_not_of(" \t"));
			value.erase(value.find_last_not_of(" \t") + 1);

			if(section == "binary") {
				if(key == "args") {
					configs._num_args = std::stoi(value);
				}
				else if(key == "min_input_len") {
					configs._min_input_len = std::stoi(value);
				}
				else if(key == "max_input_len") {
					configs._max_input_len = std::stoi(value);
				}
				else if(key == "mutate") {
					configs._mutate = std::stoi(value);	
				}
				else if(key == "mutations") {
					configs._mutations = std::stoi(value);
				}
				else if(key == "input") {
					size_t commaPos = value.find_first_of(",");
					if(commaPos == std::string::npos) { continue; }
					size_t argNum = std::stoi(value.substr(0, commaPos));
					value = value.substr(commaPos+1);
					if(argNum > configs._valid_inputs.size()) {
						configs._valid_inputs.push_back(std::vector<std::string> {});
					}
					configs._valid_inputs[argNum-1].push_back(value);
				}
			}
		}
	}
}


int main(int argc, char* argv[]) {
	// Check arguments
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

	// Set the configurations for fuzzer
	std::string configFilename = "util/configs.ini";
	fuzz::BinaryConfig configs;
	setBinaryConfigs(configs, configFilename);

	// fuzz a program 
	fuzz::fuzz_file(program, configs, 100);
	fuzz::print_statistics();

	
	// TEST
	/*
	std::cout << configs._num_args << std::endl;
	std::cout << configs._min_input_len << std::endl;
	std::cout << configs._max_input_len << std::endl;
	std::cout << configs._mutations << std::endl;
	std::cout << configs._mutate << std::endl;
	for(size_t j = 0; j < configs._valid_inputs.size(); j++) {
		for(size_t i = 0; i < configs._valid_inputs[j].size(); i++) {
			std::cout << configs._valid_inputs[j][i];
		}
	}
	*/


	return 0;
}

