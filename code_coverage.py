import frida
import sys
import time

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])

def main(target_binary, input_file):
    # Start the target process and attach using Frida
    pid = frida.spawn([target_binary, input_file])
    
    frida_session = frida.attach(pid)

    # Define the tracking script
    script_code = """
    var coveredAddresses = {};

    Stalker.follow(Process.getCurrentThreadId(), {
        events: {
            exec: true,  
        },
        onReceive: function(events) {
            var parsedEvents = Stalker.parse(events);
            parsedEvents.forEach(function(event) {
                if (event[0] === 'exec') {
                    var addr = event[1];
                    if (!coveredAddresses[addr]) {
                        coveredAddresses[addr] = true;
                    }
                }
            });
        }
    });

    function reportCoverage() {
        var uniqueCount = Object.keys(coveredAddresses).length;
        send('Code Coverage: ' + uniqueCount + ' lines covered');
    }

    // Attach to exit to ensure we always report coverage
    Interceptor.attach(Module.getExportByName(null, 'exit'), {
        onEnter: function(args) {
            reportCoverage();
        }
    });

    // Fallback to ensure coverage is reported when the script is detached
    rpc.exports = {
        report: reportCoverage
    };
    """

    script = frida_session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    
    frida.resume(pid)  # Resume the target process

    try:
        # Let the target run and periodically report coverage
        time.sleep(5)
        script.exports_sync.report()  # Ensure coverage report even if exit is not called
    finally:
        frida_session.detach()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <target_binary> <input_file>")
        sys.exit(1)
    
    target_binary = sys.argv[1]
    input_file = sys.argv[2]
    main(target_binary, input_file)
