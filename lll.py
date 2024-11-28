import subprocess

def follow_journal_logs():
    """
    Function to follow journal logs in real-time using the `journalctl` command.
    """
    # Command to follow journal logs in real-time
    command = ["journalctl", "-f"]  # -f means follow (real-time log monitoring)

    # Start the subprocess to run the journalctl command
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        while True:
            # Read one line at a time from journalctl
            line = process.stdout.readline()

            # If line is empty (no new logs), break the loop
            if not line:
                break

            # Decode and print the line (remove trailing newline)
            print(line.decode('utf-8').strip())

    except KeyboardInterrupt:
        # Stop the process if you press Ctrl+C
        process.terminate()
        print("\nReal-time monitoring stopped.")

# Call the function to start monitoring
#if __name__ == "__main__":
#    follow_journal_logs()
