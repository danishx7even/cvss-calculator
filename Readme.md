# CVSS Calculator Web App

A simple and beautiful web application for calculating CVSS (Common Vulnerability Scoring System) scores. Built with Python and Flask.

## Features

- Intuitive web interface for CVSS calculations
- Responsive design with custom CSS and JavaScript
- Easy to deploy and use

## Project Structure

```
app.py
requirements.txt
static/
    css/
        style.css
    js/
        script.js
templates/
    base.html
    index.html
```

## Getting Started

### Prerequisites

- Python 3.13+
- pip

### Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/your-username/cvss-calculator.git
    cd cvss-calculator
    ```

2. Create and activate a virtual environment:
    ```sh
    python -m venv .env
    source .env/Scripts/activate  # On Windows: .env\Scripts\activate
    ```

3. Install dependencies:
    ```sh
    pip install -r requirements.txt
    ```

### Running the App

```sh
python app.py
```

Visit [http://localhost:5000](http://localhost:5000) in your browser.

## License

This project is licensed under the MIT License.