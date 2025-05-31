#include "fuzzer.h"

using namespace fuzz;

static int segFaultNum = 0;
static int sigAbortNum = 0;
static int sigFpeNum = 0;
static int sigIllNum = 0;
static int sigBusNum = 0;
static int sigSysNum = 0;
static int numRuns = 0;

static std::random_device rd;
static std::mt19937 gen(rd());



/*
 * RNG
 */
int fuzz::rng(int a, int b) {
	std::uniform_int_distribution<int> dist(a, b);
	return dist(gen);
};

	
/*
 * Generate a random input string
 * char_code_start & char_code_end are in ascii codes
 */
std::string fuzz::generate_rand_input(int min_size, int max_size, int char_code_start, int char_code_end) {
	std::string input;
	size_t size = rng(min_size, max_size);
	for(size_t i = 0; i < size; i++) {
		char c = static_cast<char>(rng(char_code_start, char_code_end));
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
		auto a = generate_rand_input(MIN_INPUT_LEN, MAX_INPUT_LEN, 32, 127);
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
	char** args = new char*[NUM_ARGS+2];
	char** env = {NULL};
	std::string line;
	args[0] = strdup(program.c_str());
	for(int i = 1; i < NUM_ARGS+1; i++) {
		std::getline(inputFile, line);
		args[i] = strdup(line.c_str());
	} 
	args[NUM_ARGS+1] = nullptr;
	inputFile.close();

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
		if(WIFSIGNALED(status)) {
			out._signal = WTERMSIG(status);
		}
		else if(WIFEXITED(status)) {
			out._returnCode = WEXITSTATUS(status);
		}
		// Set output 
		out._stderrOutput = stderrOutput;
		out._stdoutOutput = stdoutOutput;
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
	for(int i = 0; i < NUM_ARGS + 1; i++) {
		free(args[i]);
	}
	delete[] args;
}


/*
 * Analyze the output 
 */
void fuzz::analyze_output(Input& in, Output& out) {
	std::string log = "";
	
	// Check for timeouts
	if(out._timeout) {
		log = "Timeout \t";
	}

	// Check return code
	if(out._returnCode != 0) {
		log = "Return Code \t";
	}

	// Check for signals 
	switch (out._signal) {
		case SIGSEGV:
			log = "SIGSEGV \t";
			segFaultNum++;
			break;
		case SIGABRT:
			log = "SIGABRT \t";
			sigAbortNum++;
			break;
		case SIGFPE:
			log = "SIGFPE \t";
			sigFpeNum++;
			break;
		case SIGILL:
			log = "SIGILL \t";
			sigIllNum++;
			break;
		case SIGBUS:
			log = "SIGBUS \t";
			sigBusNum++;
			break;
		case SIGSYS:
			log = "SIGSYS \t";
			sigSysNum++;
			break;
		default:
			break;
	}

	// Write to file
	std::ifstream inputFile(in._inputFile);
	if(!inputFile) { 
		std::cerr << "Failed to open file" << std::endl;
		return;
	}
	std::ostringstream buf;
	buf << inputFile.rdbuf();
	log += buf.str();

	log_results(log);
}


/*
 * Fuzz a single file
 */
void fuzz::fuzz_file(std::string binName, int epochs) {
	for(int i = 0; i < epochs; i++) {
		std::string inputFilename = "input";
		if(!setup_input_file(inputFilename)) { 
			exit(-1); 
		}

		// Initialize inputs, outputs, configurations for binary inputs
		Input in;
		in._inputFile = inputFilename;

		Output out;
		out._returnCode = 0;
		out._signal = 0;
		out._timeout = false;
		out._stderrOutput = "";
		
		// Run Program
		run_program_args(binName, in, out);

		// Analyze Results - see if anything interesting
		analyze_output(in, out);

		// DEBUG print out results
		/*
		std::cout << "Return Code: " << out._returnCode << std::endl;
		std::cout << "Signal: " << out._signal << std::endl;
		std::cout << "stderr: " << out._stderrOutput << std::endl;
		std::cout << "stdout: " << out._stdoutOutput << std::endl;
		*/
	}
	numRuns = epochs;
}


/*
 * Log any interesting results
 */
void fuzz::log_results(std::string result) {
	std::ofstream logFile(LOG_FILE, std::ios::app);
	if(!logFile) {
		std::cerr << "Error opening log file" << std::endl;
		return;
	}
	logFile << result;
	logFile.close();
}


/*
 * Print statistics
 */
void fuzz::print_statistics() {
	std::cout << "================== Fuzzing completed ==================" << std::endl;
	std::cout << "Summary of " << numRuns << " runs: " << std::endl;
	std::cout << "SIGSEGV: \t" << segFaultNum << std::endl;
}


/*
 * Mutate inputs
 */
void fuzz::mutate_input(std::string& input, int char_code_start, int char_code_end) {
	int method = rng(1,3);
	switch(method) {
		case 1:
			delete_random_char(input);
			break;
		case 2:
			insert_random_char(input, char_code_start, char_code_end);
			break;
		case 3:
			flip_random_char(input, char_code_start, char_code_end);
			break;
		default:
			break;
	}
}


/*
 * Delete a random char from input string
 */
void fuzz::delete_random_char(std::string& input) {
	int index = rng(0, input.size());
	input.erase(index, 1);
}


/*
 * Insert random char into input string
 */
void fuzz::insert_random_char(std::string& input, int char_code_start, int char_code_end) {
	size_t index = rng(0, input.size());
	char c = static_cast<char>(rng(char_code_start, char_code_end));
	input.insert(input.begin() + index, c);
}


/*
 * Flip a random input char to another
 */
void fuzz::flip_random_char(std::string& input, int char_code_start, int char_code_end) {
	size_t index = rng(0, input.size());
	char c = static_cast<char>(rng(char_code_start, char_code_end));
	input[index] = c;
}

