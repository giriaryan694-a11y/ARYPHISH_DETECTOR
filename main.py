import os
import asyncio
import httpx  # For asynchronous web requests
import google.generativeai as genai
import openai
from flask import Flask, request, jsonify, render_template_string

# --- NEW: CLI Styling Imports ---
import pyfiglet
import colorama
from colorama import Fore, Style

# Initialize Colorama for cross-platform colored text
colorama.init(autoreset=True)
# --- End NEW ---

# --- Configuration ---

# DEFAULT System prompt to instruct the AIs
AI_SYSTEM_PROMPT = """
You are an expert cybersecurity analyst specializing in phishing detection.
Your task is to analyze a given URL and its HTML source code to determine if it is a phishing website or a safe website.
Provide a clear one-word verdict: 'Safe' or 'Phishing'.
Then, provide a concise, one-paragraph explanation for your reasoning.
Format your response as:
Verdict: [Safe/Phishing]
Reasoning: [Your one-paragraph explanation]
"""

# --- 1. Load API Keys ---

def load_api_keys(filepath="keys.txt"):
    """
    Reads API keys from a specified file.
    """
    keys = {}
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    key, value = line.split('=', 1)
                    keys[key.strip()] = value.strip()
                except ValueError:
                    print(f"Warning: Skipping malformed line in {filepath}: {line}")
    except FileNotFoundError:
        print(f"{Fore.RED}Error: {filepath} not found. Please create it with your API keys.")
        return None
    except Exception as e:
        print(f"{Fore.RED}Error reading {filepath}: {e}")
        return None
        
    # UPDATED: Check if AT LEAST ONE key is present, not both
    if 'GEMINI_API' not in keys and 'CHATGPT_API' not in keys:
        print(f"{Fore.RED}Error: At least one API key (GEMINI_API or CHATGPT_API) must be in keys.txt")
        return None
        
    return keys

# --- 2. Configure AI Clients ---

api_keys = load_api_keys()
if api_keys:
    # Configure Gemini
    try:
        if 'GEMINI_API' in api_keys:
            genai.configure(api_key=api_keys.get('GEMINI_API'))
            gemini_model = genai.GenerativeModel('gemini-2.5-flash-preview-09-2025')
        else:
            gemini_model = None
    except Exception as e:
        print(f"{Fore.RED}Error configuring Gemini: {e}")
        gemini_model = None

    # Configure OpenAI
    try:
        if 'CHATGPT_API' in api_keys:
            openai_client = openai.AsyncOpenAI(api_key=api_keys.get('CHATGPT_API'))
        else:
            openai_client = None
    except Exception as e:
        print(f"{Fore.RED}Error configuring OpenAI: {e}")
        openai_client = None
else:
    gemini_model = None
    openai_client = None

# --- 3. Asynchronous AI Analysis Functions ---

async def fetch_website_content(url: str) -> str:
    """Asynchronously fetches the HTML content of a URL."""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()  # Raise an exception for bad status codes
            return response.text
    except httpx.HTTPStatusError as e:
        print(f"{Fore.RED}HTTP error fetching {url}: {e}")
        raise Exception(f"Failed to fetch content (Status: {e.response.status_code}). Site may be down.")
    except httpx.RequestError as e:
        print(f"{Fore.RED}Request error fetching {url}: {e}")
        raise Exception("Could not retrieve website content. The site might be offline or unreachable.")

async def analyze_with_gemini(user_prompt: str, system_prompt: str) -> str:
    """Analyzes content with Gemini, using a provided system prompt."""
    if not gemini_model:
        return "Error: Gemini model is not configured or API key is missing."
    try:
        full_prompt = f"{system_prompt}\n\n---\n\n{user_prompt}"
        response = await gemini_model.generate_content_async(full_prompt)
        return response.text
    except Exception as e:
        print(f"{Fore.RED}Gemini API error: {e}")
        return f"Error during Gemini analysis: {e}"

async def analyze_with_openai(user_prompt: str, system_prompt: str) -> str:
    """Analyzes content with OpenAI (ChatGPT), using a provided system prompt."""
    if not openai_client:
        return "Error: OpenAI client is not configured or API key is missing."
    try:
        response = await openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.1
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"{Fore.RED}OpenAI API error: {e}")
        return f"Error during OpenAI analysis: {e}"

# --- 4. Flask Web Server ---

app = Flask(__name__)

# UPDATED: Added 'r' before the string to make it a raw string
HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ARYPHISH_DETECTOR</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { font-family: 'Inter', sans-serif; }
        .loader {
            border: 4px solid #374151; /* gray-700 */
            border-top: 4px solid #3b82f6; /* blue-500 */
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .result-card {
            border: 1px solid #374151; /* gray-700 */
            border-radius: 0.5rem;
            background-color: #1f2937; /* gray-800 */
        }
        .result-card h3 {
            border-bottom: 1px solid #374151; /* gray-700 */
        }
        .verdict-safe { color: #22c55e; /* green-500 */ }
        .verdict-phishing { color: #ef4444; /* red-500 */ }
    </style>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
</head>
<body class="bg-gray-900 text-gray-100 flex items-center justify-center min-h-screen p-4">

    <div class="w-full max-w-3xl">
        <div class="bg-gray-800 rounded-lg shadow-2xl p-6 md:p-8">
            <h1 class="text-4xl font-bold text-center text-blue-400 mb-2">ARYPHISH_DETECTOR</h1>
            <p class="text-center text-lg text-gray-400 mb-6">AI Phishing Analysis Tool</p>
            
            <form id="analyzeForm" class="space-y-4">
                <div>
                    <label for="urlInput" class="block mb-2 text-sm font-medium text-gray-300">URL to Analyze</label>
                    <input type="url" id="urlInput" placeholder="https://example.com" required
                           class="bg-gray-700 border border-gray-600 text-gray-100 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-3">
                </div>
                <div>
                    <label for="aiChoice" class="block mb-2 text-sm font-medium text-gray-300">Choose AI Model</label>
                    <select id="aiChoice"
                            class="bg-gray-700 border border-gray-600 text-gray-100 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-3">
                        <option value="both" selected>Both (Gemini & ChatGPT)</option>
                        <option value="gemini">Gemini Only</option>
                        <option value="chatgpt">ChatGPT Only</option>
                    </select>
                </div>
                
                <!-- REMOVED: Custom Prompt Textarea -->

                <button type="submit" id="checkButton"
                        class="w-full text-white bg-blue-600 hover:bg-blue-700 focus:ring-4 focus:outline-none focus:ring-blue-800 font-medium rounded-lg text-sm px-5 py-3 text-center transition-colors">
                    Analyze
                </button>
            </form>
        </div>

        <!-- Loading Spinner -->
        <div id="loadingSpinner" class="hidden flex-col items-center justify-center pt-10">
            <div class="loader"></div>
            <p class="text-gray-400 mt-4">Analyzing... This may take a moment.</p>
        </div>

        <!-- Error Message -->
        <div id="errorMessage" class="hidden text-red-300 bg-red-900/50 p-4 rounded-lg text-center font-medium mt-6">
            <!-- Error messages -->
        </div>

        <!-- Results Section -->
        <div id="resultsContainer" class="hidden grid grid-cols-1 md:grid-cols-2 gap-6 mt-6">
            
            <!-- Gemini Result -->
            <div id="geminiCard" class="result-card hidden">
                <h3 class="text-xl font-semibold p-4 text-gray-200">Gemini Analysis</h3>
                <div id="geminiResult" class="p-4 space-y-2">
                    <!-- JS will populate this -->
                </div>
            </div>
            
            <!-- ChatGPT Result -->
            <div id="chatgptCard" class="result-card hidden">
                <h3 class="text-xl font-semibold p-4 text-gray-200">ChatGPT Analysis</h3>
                <div id="chatgptResult" class="p-4 space-y-2">
                    <!-- JS will populate this -->
                </div>
            </div>
        </div>
        
        <!-- NEW: Credit Footer -->
        <footer class="text-center mt-6">
            <p class="text-gray-500 text-sm">Made By Aryan Giri</p>
        </footer>

    </div>

    <script>
        console.log("Script starting. Attaching form listener...");
        
        document.getElementById('analyzeForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            console.log("Form submitted. Analyzing...");
            
            const url = document.getElementById('urlInput').value;
            const aiChoice = document.getElementById('aiChoice').value;
            
            const checkButton = document.getElementById('checkButton');
            const loadingSpinner = document.getElementById('loadingSpinner');
            const resultsContainer = document.getElementById('resultsContainer');
            const errorMessage = document.getElementById('errorMessage');
            
            // Reset UI
            checkButton.disabled = true;
            checkButton.textContent = 'Analyzing...';
            loadingSpinner.classList.remove('hidden');
            loadingSpinner.classList.add('flex');
            resultsContainer.classList.add('hidden');
            errorMessage.classList.add('hidden');
            document.getElementById('geminiCard').classList.add('hidden');
            document.getElementById('chatgptCard').classList.add('hidden');

            try {
                const response = await fetch('/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        url: url, 
                        ai_choice: aiChoice
                    })
                });
                
                console.log("Fetch response received:", response);

                if (!response.ok) {
                    const errData = await response.json();
                    console.error("Server returned an error:", errData);
                    throw new Error(errData.error || 'An unknown server error occurred.');
                }

                const data = await response.json();
                console.log("Response data parsed:", data);
                
                // Display results
                if (data.gemini) {
                    console.log("Populating Gemini:", data.gemini);
                    document.getElementById('geminiResult').innerHTML = formatResult(data.gemini);
                    document.getElementById('geminiCard').classList.remove('hidden');
                }
                if (data.chatgpt) {
                    console.log("Populating ChatGPT:", data.chatgpt);
                    document.getElementById('chatgptResult').innerHTML = formatResult(data.chatgpt);
                    document.getElementById('chatgptCard').classList.remove('hidden');
                }
                
                resultsContainer.classList.remove('hidden');
                console.log("Results displayed.");

            } catch (error) {
                console.error('Fetch Error:', error);
                errorMessage.textContent = error.message;
                errorMessage.classList.remove('hidden');
            } finally {
                checkButton.disabled = false;
                checkButton.textContent = 'Analyze';
                loadingSpinner.classList.add('hidden');
                loadingSpinner.classList.remove('flex');
                console.log("Analysis complete. UI reset.");
            }
        });

        function formatResult(text) {
            console.log("Formatting result for:", text);
            if (text.startsWith('Error:')) {
                console.log("Formatting as error.");
                return `<p class="text-red-400">${text}</p>`;
            }
            
            let verdict = "Unknown";
            let reasoning = text;
            
            const verdictMatch = text.match(/Verdict:\s*(Safe|Phishing)/i);
            const reasoningMatch = text.match(/Reasoning:\s*([\s\S]*)/i);

            let verdictClass = "";
            if (verdictMatch) {
                verdict = verdictMatch[1];
                if (verdict.toLowerCase() === 'safe') verdictClass = 'verdict-safe';
                if (verdict.toLowerCase() === 'phishing') verdictClass = 'verdict-phishing';
            }
            
            if (reasoningMatch) {
                reasoning = reasoningMatch[1].trim();
            }
            
            console.log("Verdict:", verdict, "Reasoning:", reasoning);

            // *** THE FIX IS HERE ***
            // Removed the bad backslashes `\` before the backticks
            return `
                <p class="text-lg font-medium"><strong>Verdict: <span class="${verdictClass}">${verdict}</span></strong></p>
                <p class="text-sm text-gray-300">${reasoning}</p>
            `;
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    """Serves the main HTML page."""
    # UPDATED: Removed default_prompt from render
    return render_template_string(HTML_TEMPLATE)

# --- NEW: Asynchronous helper function ---
async def perform_analysis(url, ai_choice, system_prompt):
    """
    This helper function runs all the async code (fetching, AI calls)
    and returns a dictionary and a status code.
    """
    # --- Fetch Website Content ---
    try:
        source_code = await fetch_website_content(url)
        truncated_source_code = source_code[:15000]
        user_prompt = f"URL: {url}\n\nSOURCE CODE (first 15,000 characters):\n{truncated_source_code}"
    except Exception as e:
        return {"error": str(e)}, 400

    # --- Run AI Analyses in Parallel ---
    tasks = []
    if ai_choice in ['gemini', 'both']:
        tasks.append(analyze_with_gemini(user_prompt, system_prompt))
    if ai_choice in ['chatgpt', 'both']:
        tasks.append(analyze_with_openai(user_prompt, system_prompt))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # --- Format Response ---
    response_data = {}
    result_index = 0
    
    if ai_choice in ['gemini', 'both']:
        if isinstance(results[result_index], Exception):
            response_data['gemini'] = f"Error: {results[result_index]}"
        else:
            response_data['gemini'] = results[result_index]
        result_index += 1

    if ai_choice in ['chatgpt', 'both']:
        if isinstance(results[result_index], Exception):
            response_data['chatgpt'] = f"Error: {results[result_index]}"
        else:
            response_data['chatgpt'] = results[result_index]
    
    return response_data, 200
# --- End of new helper function ---


# UPDATED: Flask route is now SYNCHRONOUS
@app.route('/analyze', methods=['POST'])
def analyze():
    """Handles the analysis request from the frontend."""
    # UPDATED: Check if AT LEAST ONE model is configured
    if not api_keys or (not gemini_model and not openai_client):
        return jsonify({"error": "Server is not configured with at least one valid API key."}), 500
        
    try:
        # This part is synchronous
        data = request.get_json()
        
        url = data.get('url')
        ai_choice = data.get('ai_choice')

        if not url:
            return jsonify({"error": "URL is required."}), 400
            
        system_prompt = AI_SYSTEM_PROMPT

        # UPDATED: Run the async helper function using asyncio.run()
        # This correctly calls the async code from our sync function
        response_data, status_code = asyncio.run(perform_analysis(url, ai_choice, system_prompt))
        
        return jsonify(response_data), status_code

    except Exception as e:
        print(f"{Fore.RED}Server error: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500

# --- 5. Run the Application ---

def print_cli_banner():
    """Prints a stylish banner to the console when the app starts."""
    print(Style.BRIGHT)
    # You can change the font to others like 'standard', 'slant', 'big'
    banner_text = pyfiglet.figlet_format("ARYPHISH_DETECTOR", font="slant")
    print(f"{Fore.CYAN}{banner_text}")
    print(f"{Fore.YELLOW}Made By Aryan Giri\n{Style.RESET_ALL}")
    
    # UPDATED: Check if AT LEAST ONE model is configured
    if not api_keys or (not gemini_model and not openai_client):
        print("---")
        print(f"{Fore.RED}Error: The application cannot start. At least one valid API key is required.")
        print(f"{Fore.WHITE}Please ensure 'keys.txt' exists and contains at least one of:")
        print("GEMINI_API=your_key")
        print("CHATGPT_API=your_key")
        print("---")
        return False
    else:
        if gemini_model:
            print(f"{Fore.GREEN}✓ Gemini Model Configured")
        else:
            print(f"{Fore.YELLOW}✗ Gemini Model not configured (API key missing or invalid)")
            
        if openai_client:
            print(f"{Fore.GREEN}✓ OpenAI Client Configured")
        else:
            print(f"{Fore.YELLOW}✗ OpenAI Client not configured (API key missing or invalid)")

        print("---")
        print(f"{Fore.GREEN}Flask server starting...")
        print(f"{Fore.WHITE}Open http://127.0.0.1:5000 in your browser.")
        print("---")
        return True

if __name__ == '__main__':
    if print_cli_banner():
        # Runs the app on localhost, port 5000
        app.run(debug=True, host='127.0.0.1', port=5000)
                                                          
