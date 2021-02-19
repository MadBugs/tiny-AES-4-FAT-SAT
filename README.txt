# ------------------------------------------------------------------
# PLEASE NOTE: This code runs in Linux (Fully tested), 
# It also runs on Windows/Cygowin (issues with the qsort() call, but still works
# and Perhaps in Apples OS (not tested)
# ------------------------------------------------------------------
# ALSO use 'less -rS' instead of less or more so the color chars will not
# makes the terminal to wrap-up
# ------------------------------------------------------------------

*** To Build:
just type 'make' (or if the case make -f <makefile_name>)

*** To Run: 
# STEP 00:
# To get some minimalistic help just type the name of the program
$ ./AES_fault_attack_01_main
SYNTAX: ./AES_fault_attack_01_main ATTACK_TYPE  [number_of_runs  stats]
ATTACK_TYPE can be 0|1|2|21|23|-1|-2
PLEASE choose one of the numbers displayed above
Have a good day..

# STEP 01:
# Run case 01 (attack 01) using Giraud's method
# The line below will perform the atack 01 (a la Giraud) for 10 random runs
#
./AES_fault_attack_01_main 1 1  | less -rS


# STEP 01:
# Run case 02 (attack 02) using the stastistical analysis method (for 10 random runs)
# The option 'stats' enables some addition useful statistics to be printed
# It takes around 20 seconds to each run to complete
#
./AES_fault_attack_01_main 2 1 stats | less -rS

# To filter only the main key elements of the report do grep filter as below
#
./AES_fault_attack_01_main 2 1 stats | egrep "KEYM|COUNTx" | less -rS

# STEP 03:
# The statistical approach also works for the Attack01!!!
# Runs the lines below to check
#
./AES_fault_attack_01_main 21 1 stats | less -rS
 
# and
./AES_fault_attack_01_main 21 1 stats | egrep "KEYM|COUNTx" | less -rS

# PLEASE NOTE: To do less -rS than 1 random run, just replace the 1 
# in the commands above with the desired number of runs

