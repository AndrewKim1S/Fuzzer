#pragma once

#include <iostream>
#include <random>
#include <fstream>
#include <chrono>
#include <cstring>
#include <unistd.h>
#include <sys/wait.h>


namespace fuzz {

// Constants 
const int MAX_RUNTIME = 600; // 10 min
const int NUM_INPUTS = 10;
const int MIN_INPUT_LEN = 10;
const int MAX_INPUT_LEN = 80;
const int NUM_ARGS = 10;
const std::string WORKING_DIR = "/home/sheehyun/dev/AEG/Fuzzing";


// Structs
struct Input {
	std::string _inputFile;
};

struct Output {
	int _returnCode;
	bool _timeout;
	std::string _stderrOutput;
};

struct BinaryConfig {
	bool _args;
	bool _stdins;
};


// Functions
std::string generate_rand_input(int min_size, int max_size, int char_code_start, int char_code_end);
bool setup_input_file(std::string filename);
void run_program_args(std::string& program, Input& in, Output& out);
void fuzz_file(std::string binName, int epochs);

}
