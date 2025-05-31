#pragma once

#include <iostream>
#include <random>
#include <fstream>
#include <chrono>
#include <sstream>

#include <cstring>
#include <unistd.h>
#include <sys/wait.h>


namespace fuzz {

// Constants 
const int MAX_RUNTIME = 600; // 10 min
const int NUM_INPUTS = 1;
const int MIN_INPUT_LEN = 1;
const int MAX_INPUT_LEN = 100;
const int NUM_ARGS = 1;
const std::string WORKING_DIR = "/home/sheehyun/dev/AEG/Fuzzing";
const std::string LOG_FILE = "log";

// Structs
struct Input {
	std::string _inputFile;
};

struct Output {
	int _returnCode;
	int _signal;
	bool _timeout;
	std::string _stderrOutput;
	std::string _stdoutOutput;
};

struct BinaryConfig {
	bool _args;
	bool _stdins;
};


// Functions
int rng(int a, int b);
std::string generate_rand_input(int min_size, int max_size, int char_code_start, int char_code_end);
bool setup_input_file(std::string filename);
void run_program_args(std::string& program, Input& in, Output& out);
void analyze_output(Input& in, Output& out);
void fuzz_file(std::string binName, int epochs);
void log_results(std::string result);
void print_statistics();

// Mutating inputs
void mutate_input(std::string& input, int char_code_start, int char_code_end);
void delete_random_char(std::string& input);
void insert_random_char(std::string& input, int char_code_start, int char_code_end);
void flip_random_char(std::string& input, int char_code_start, int char_code_end);
}
