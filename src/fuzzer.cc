#include "fuzzer.h"

using namespace fuzz;

/*
 * Generate a random input string
 * char_code_start & char_code_end are in ascii codes
 */
std::string fuzz::generate_rand_input(int min_size, int max_size, int char_code_start, int char_code_end) {
	static std::random_device rd;
	static std::mt19937 gen(rd());
	
	auto rand = [&](int a, int b){
		std::uniform_int_distribution<int> dist(a, b);
		return dist(gen);
	};
		
	std::string input;
	size_t size = rand(min_size, max_size);
	for(size_t i = 0; i < size; i++) {
		char c = static_cast<char>(rand(char_code_start, char_code_end));
		input += c;
	}
	return input;
}


/*
 * Generate random inputs and place them into a file
 */
bool fuzz::setup_input_file(std::string filename) {
	std::ofstream file(filename);
	if(!file) {
		std::cerr << "Error opening file\n";
		return false;
	}
	for(int i = 0; i < fuzz::NUM_INPUTS; i++) {
		auto a = generate_rand_input(MIN_INPUT_LEN, MAX_INPUT_LEN, 32, 64);
		file << a;
		file << "\n";
	}
	file.close();
	return true;
}


/*
 * Invoke External Program
 */
void fuzz::run_program_args(std::string& program, Input& in, Output& out) {
	// Setup input & output pipes
	int stdinPipe[2];
	int stdoutPipe[2];
	int stderrPipe[2];
	if(pipe(stdinPipe) != 0 || pipe(stdoutPipe) || pipe(stderrPipe)) {
		std::cerr << "Error initializing pipe\n" << std::endl;
	}

	// Setup inputs
	std::ifstream inputFile(in._inputFile);
	if(!inputFile) {
		std::cerr << "Error opening input file for reading\n" << std::endl;
		exit(-1);
	}
	char** args = new char*[NUM_ARGS+1];
	char** env = {NULL};
	std::string line;
	for(int i = 0; i < NUM_ARGS; i++) {
		std::getline(inputFile, line);
		args[i] = strdup(line.c_str());
	} 
	inputFile.close();
	args[NUM_ARGS] = nullptr;

	// Setup time
	auto startTime = std::chrono::steady_clock::now();
	
	// Fork process
	pid_t pid = fork();

	// Child 
	if(pid == 0) {
		close(stdinPipe[1]);
		close(stdoutPipe[0]);
		close(stderrPipe[0]);
		
		dup2(stdinPipe[0], STDIN_FILENO);
		dup2(stdoutPipe[1], STDOUT_FILENO);
		dup2(stderrPipe[1], STDERR_FILENO);

		execve(program.c_str(), args, env);

		std::cerr << "Error exec child proc failed" << std::endl;
		exit(-1);
	} 
	// Parent
	else if (pid > 0){
		close(stdinPipe[0]);
		close(stdoutPipe[1]);
		close(stderrPipe[1]);
		
		// Read the Child's output
		int status = 0;
		char buffer[1024];
		size_t bytes = 0;
		std::string stdoutOutput;
		std::string stderrOutput;

		// Keep track of time
		int elapsed = 0;

		// Capture stdout and stderr from program
		while(waitpid(pid, &status, WNOHANG) == 0 && elapsed < MAX_RUNTIME) {
			bytes = read(stdoutPipe[0], buffer, sizeof(buffer));
			if(bytes > 0) {
				stdoutOutput.append(buffer, bytes);
			}
			bytes = read(stderrPipe[0], buffer, sizeof(buffer));
			if(bytes > 0) {
				stderrOutput.append(buffer, bytes);
			}
			elapsed = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - startTime).count();
		}
		waitpid(pid, &status, 0);

		// Set return code
		if(WIFEXITED(status)) {
			out._returnCode = WEXITSTATUS(status);
		}
		// Set output 
		out._stderrOutput = stderrOutput;
		if(elapsed > MAX_RUNTIME) {
			out._timeout = true;
		}
	}
	// Error in fork
	else {
		std::cerr << "Error fork\n" << std::endl;
		exit(-1);
	}

	// Free allocated args
	for(int i = 0; args[i] != nullptr; i++) {
		free(args[i]);
	}
	delete[] args;
}


/*
 * Fuzz a single file
 */
void fuzz::fuzz_file(std::string binName, int epochs) {
	std::string inputFilename = "input";
	if(!setup_input_file(inputFilename)) { 
		exit(-1); 
	}

	// Initialize inputs, outputs, configurations for binary inputs
	Input in;
	in._inputFile = inputFilename;

	Output out;
	out._returnCode = 0;
	out._timeout = false;
	out._stderrOutput = "";
	
	// Run Program
	run_program_args(binName, in, out);

	// Analyze Results - see if anything interesting

	// DEBUG print out results
	std::cout << "Return Code: " << out._returnCode << std::endl;
	std::cout << "stderr: " << out._stderrOutput << std::endl;
}

