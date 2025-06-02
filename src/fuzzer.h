#pragma once

#include <iostream>
#include <random>
#include <fstream>
#include <chrono>
#include <sstream>
#include <algorithm>

#include <cstring>
#include <unistd.h>
#include <sys/wait.h>


namespace fuzz {

// Constants 
const int MAX_RUNTIME = 600; // 10 min
const std::string WORKING_DIR = "/home/sheehyun/dev/AEG/Fuzzing";
const std::string LOG_FILE = "log";
const int CHAR_CODE_START = 32;
const int CHAR_CODE_END = 127;


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
	int _num_args;
	int _min_input_len;
	int _max_input_len;
	bool _mutate;
	int _mutations;
	std::vector<std::vector<std::string>> _valid_inputs;
};

struct FuzzerConfig {
	int _num_epochs;
};


// Functions
int rng(int a, int b);
std::string generate_rand_input(int min_size, int max_size, int char_code_start, int char_code_end);
bool setup_input_file_random(std::string filename);
void setup_arg_mutations(std::vector<std::vector<std::string>>& _valid_inputs);
bool setup_input_file_mutation(std::string filename, std::vector<std::vector<std::string>>& _valid_inputs);
void run_program_args(std::string& program, Input& in, Output& out);
void analyze_output(Input& in, Output& out);
void fuzz_file(std::string binName, BinaryConfig& configs, int epochs);
void log_results(std::string result);
void print_statistics();

// Mutating inputs
void mutate_input(std::string& input, int char_code_start, int char_code_end);
void delete_random_char(std::string& input);
void insert_random_char(std::string& input, int char_code_start, int char_code_end);
void flip_random_char(std::string& input, int char_code_start, int char_code_end);

}

