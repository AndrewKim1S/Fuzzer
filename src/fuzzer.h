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

extern char **environ;


namespace fuzz {

// Constants 
const int MAX_RUNTIME = 600; // 10 min
const std::string WORKING_DIR = "/home/sheehyun/dev/AEG/Fuzzing";
const std::string LOG_FILE = "log";
const int CHAR_CODE_START = 32;
const int CHAR_CODE_END = 127;
const std::vector<std::string> env_vars = {"PATH", "LD_PRELOAD", "USER"};



// Structs
struct Input {
	std::string _inputFile;
	std::vector<std::string> _argInputs;
	std::vector<std::string> _envVariables;
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
std::string generate_rand_string(int min_size, int max_size, int char_code_start, int char_code_end);

// Input generation for args
bool setup_input_arg_random(Input& in);
bool setup_input_arg_mutation(Input& in, std::vector<std::vector<std::string>>& _valid_inputs);
void setup_arg_mutations(std::vector<std::vector<std::string>>& _valid_inputs);

// Input generation for env vars
void setup_env_variables();

void setup_input(std::vector<std::string>& inputs, char**& env, int len, int start);

void run_program_args(std::string& program, Input& in, Output& out);
void analyze_output(Input& in, Output& out);
void fuzz_file(std::string binName, BinaryConfig& configs, int epochs);
void log_results(std::string result);
void print_statistics();

// Mutating argument inputs
void mutate_input(std::string& input, int char_code_start, int char_code_end);
void delete_random_char(std::string& input);
void insert_random_char(std::string& input, int char_code_start, int char_code_end);
void flip_random_char(std::string& input, int char_code_start, int char_code_end);

}

