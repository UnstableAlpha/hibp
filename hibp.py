#!/usr/bin/env python3
"""
HIBP Checker - A command-line tool to query the 'Have I Been Pwned' API.

This tool allows security professionals to check if email addresses or passwords
have been compromised in known data breaches. Password checks use the k-anonymity
model to ensure the full password is never sent over the network.
"""

import argparse
import hashlib
import json
import sys
import time
import requests
import os
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

# Set up rich console for better terminal output
console = Console()

class HIBPChecker:
    """Class to handle interactions with the Have I Been Pwned API."""
    
    def __init__(self, api_key=None, rate_limit=True):
        """Initialize the HIBP Checker with an optional API key."""
        self.api_key = api_key
        self.base_url = "https://haveibeenpwned.com/api/v3"
        self.user_agent = "HIBPChecker-CLI"
        self.rate_limit = rate_limit
        self.last_request_time = 0
        # Set minimum request interval to 6.5 seconds to ensure we stay safely under the limit
        self.min_request_interval = 6.5 if rate_limit else 0
        
    def _apply_rate_limit(self):
        """Apply rate limiting to respect API constraints."""
        if self.rate_limit:
            current_time = time.time()
            elapsed = current_time - self.last_request_time
            
            # If we need to wait to respect rate limits
            if elapsed < self.min_request_interval:
                wait_time = self.min_request_interval - elapsed
                # Don't use a status display here - just print a message and wait
                console.print(f"[yellow]Rate limiting: waiting {wait_time:.1f} seconds...[/yellow]")
                time.sleep(wait_time)
                    
            # Update the last request time
            self.last_request_time = time.time()

    def check_email(self, email):
        """
        Check if an email has been found in data breaches.
        
        Args:
            email: The email address to check.
            
        Returns:
            List of breaches or None if no breaches found.
        """
        if not self.api_key:
            console.print("[bold red]Error:[/bold red] API key is required for email checks.", style="red")
            return None
            
        # Apply rate limiting before making the request
        self._apply_rate_limit()
            
        endpoint = f"{self.base_url}/breachedaccount/{email}?truncateResponse=false"
        headers = {
            "User-Agent": self.user_agent,
            "hibp-api-key": self.api_key,
        }
        
        try:
            # Print status instead of using status context manager to avoid nesting issues
            console.print(f"[bold blue]Checking email address: {email}...[/bold blue]")
            response = requests.get(endpoint, headers=headers)
                
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return []
            elif response.status_code == 429:
                console.print("[bold yellow]Rate limit exceeded. Please wait and try again.", style="yellow")
            else:
                console.print(f"[bold red]Error:[/bold red] API returned status code {response.status_code}", style="red")
                
        except requests.exceptions.RequestException as e:
            console.print(f"[bold red]Error:[/bold red] {str(e)}", style="red")
            
        return None
    
    def check_password(self, password):
        """
        Check if a password has been exposed in data breaches.
        Uses k-anonymity model to protect the password.
        
        Args:
            password: The password to check.
            
        Returns:
            The number of times the password was found in breaches, or 0 if not found.
        """
        # Apply rate limiting before making the request
        self._apply_rate_limit()
        
        # Create SHA-1 hash of the password
        password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        
        # Get the first 5 characters of the hash (prefix)
        prefix = password_hash[:5]
        
        # Get the remainder of the hash (we'll search for this in the response)
        suffix = password_hash[5:]
        
        # Query the API with just the prefix
        endpoint = f"https://api.pwnedpasswords.com/range/{prefix}"
        headers = {"User-Agent": self.user_agent}
        
        try:
            # Print status instead of using status context manager
            console.print("[bold blue]Checking password securely...[/bold blue]")
            response = requests.get(endpoint, headers=headers)
                
            if response.status_code == 200:
                hash_counts = {}
                
                # Parse the response which contains suffixes and counts
                for line in response.text.splitlines():
                    # Each line is in the format: SUFFIX:COUNT
                    hash_suffix, count = line.split(':')
                    hash_counts[hash_suffix] = int(count)
                
                # Check if our password suffix is in the results
                if suffix in hash_counts:
                    return hash_counts[suffix]
                else:
                    return 0
                    
            else:
                console.print(f"[bold red]Error:[/bold red] API returned status code {response.status_code}", style="red")
                
        except requests.exceptions.RequestException as e:
            console.print(f"[bold red]Error:[/bold red] {str(e)}", style="red")
            
        return None

    def get_breach_details(self, breach_name):
        """
        Get detailed information about a specific breach.
        
        Args:
            breach_name: The name of the breach to retrieve information for.
            
        Returns:
            Dictionary with breach details or None if not found.
        """
        if not self.api_key:
            console.print("[bold red]Error:[/bold red] API key is required for breach details.", style="red")
            return None
            
        # Apply rate limiting before making the request
        self._apply_rate_limit()
            
        endpoint = f"{self.base_url}/breach/{breach_name}"
        headers = {
            "User-Agent": self.user_agent,
            "hibp-api-key": self.api_key,
        }
        
        try:
            # Print status instead of using status context manager
            console.print(f"[bold blue]Fetching details for {breach_name}...[/bold blue]")
            response = requests.get(endpoint, headers=headers)
                
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                console.print(f"[bold yellow]Breach {breach_name} not found.", style="yellow")
            elif response.status_code == 429:
                console.print("[bold yellow]Rate limit exceeded. Please wait and try again.", style="yellow")
            else:
                console.print(f"[bold red]Error:[/bold red] API returned status code {response.status_code}", style="red")
                
        except requests.exceptions.RequestException as e:
            console.print(f"[bold red]Error:[/bold red] {str(e)}", style="red")
            
        return None
        
    def check_emails_from_file(self, file_path, output_file=None):
        """
        Check multiple email addresses from a file.
        
        Args:
            file_path: Path to the file containing email addresses (one per line).
            output_file: Optional path to save results to a file.
            
        Returns:
            Dictionary mapping email addresses to breach results.
        """
        if not self.api_key:
            console.print("[bold red]Error:[/bold red] API key is required for email checks.", style="red")
            return None
            
        # Check if file exists
        path = Path(file_path)
        if not path.exists() or not path.is_file():
            console.print(f"[bold red]Error:[/bold red] File not found: {file_path}", style="red")
            return None
            
        try:
            # Read email addresses from the file
            with open(file_path, 'r') as f:
                emails = [line.strip() for line in f if line.strip()]
                
            if not emails:
                console.print("[bold yellow]Warning:[/bold yellow] No email addresses found in the file.", style="yellow")
                return {}
                
            # Create results dictionary and timestamp for the run
            results = {}
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            
            # Set up output file if requested
            output_handle = None
            if output_file:
                try:
                    output_handle = open(output_file, 'w')
                    output_handle.write(f"# HIBP Email Check Results - {timestamp}\n\n")
                except IOError as e:
                    console.print(f"[bold red]Error:[/bold red] Could not open output file: {str(e)}", style="red")
                    output_file = None
            
            # Display progress information
            console.print(f"\n[bold]Checking [cyan]{len(emails)}[/cyan] email addresses (max 9 per minute)...[/bold]\n")
            
            # Process each email without using nested status displays
            for i, email in enumerate(emails):
                # Show which email we're processing
                console.print(f"[blue]Processing email {i+1}/{len(emails)}: {email}[/blue]")
                
                # Check this email
                breaches = self.check_email(email)
                results[email] = breaches
                
                # Display immediate result with detailed breach information
                if breaches is None:
                    console.print(f"[yellow]Error checking {email}[/yellow]")
                elif not breaches:
                    console.print(f"[green]No breaches found for {email}[/green]")
                else:
                    console.print(f"[red]Found {len(breaches)} breaches for {email}:[/red]")
                    
                    # Create a mini-table showing the breach details for this email
                    breach_table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
                    breach_table.add_column("Breach Name", style="cyan")
                    breach_table.add_column("Date", style="yellow")
                    breach_table.add_column("Data Types", style="green", width=40)
                    
                    for breach in breaches:
                        date = breach.get("BreachDate", "Unknown")
                        name = breach.get("Name", "Unknown")
                        data_classes = ", ".join(breach.get("DataClasses", [])[0:5])
                        if len(breach.get("DataClasses", [])) > 5:
                            data_classes += "..."
                        breach_table.add_row(name, date, data_classes)
                    
                    console.print(breach_table)
                
                # Write to output file if specified
                if output_handle:
                    output_handle.write(f"## Email: {email}\n")
                    if breaches is None:
                        output_handle.write("Error checking this email.\n\n")
                    elif not breaches:
                        output_handle.write("No breaches found.\n\n")
                    else:
                        output_handle.write(f"Found in {len(breaches)} breaches:\n")
                        for breach in breaches:
                            output_handle.write(f"- {breach.get('Name', 'Unknown')}: {breach.get('BreachDate', 'Unknown')} ")
                            output_handle.write(f"({', '.join(breach.get('DataClasses', []))})\n")
                        output_handle.write("\n")
                    output_handle.flush()
                
                # Display progress summary at intervals
                if (i + 1) % 5 == 0 or (i + 1) == len(emails):
                    console.print(f"[green]Progress: {i+1}/{len(emails)} emails processed[/green]")
                    
                # Add a newline for spacing
                if i < len(emails) - 1:
                    console.print("")
            
            # Close output file if opened
            if output_handle:
                output_handle.close()
                console.print(f"\n[green]Results saved to: {output_file}[/green]")
                
            return results
                
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {str(e)}", style="red")
            if 'output_handle' in locals() and output_handle:
                output_handle.close()
            return None

    def display_email_results(self, email, breaches):
        """Display the results of an email check in a nicely formatted table."""
        if breaches is None:
            return
            
        if not breaches:
            console.print(Panel(
                f"[bold green]Good news![/bold green] The email address [bold]{email}[/bold] was not found in any known data breaches.",
                title="Email Check Results",
                border_style="green"
            ))
            return
            
        console.print(Panel(
            f"[bold red]Warning![/bold red] The email address [bold]{email}[/bold] was found in [bold red]{len(breaches)}[/bold red] data breaches.",
            title="Email Check Results",
            border_style="red"
        ))
        
        table = Table(show_header=True, header_style="bold", box=box.ROUNDED)
        table.add_column("Breach Name", style="cyan")
        table.add_column("Date", style="yellow")
        table.add_column("Compromised Accounts", style="red")
        table.add_column("Data Types", style="green", width=40)
        
        for breach in breaches:
            date = breach.get("BreachDate", "Unknown")
            name = breach.get("Name", "Unknown")
            account_count = f"{breach.get('PwnCount', 0):,}"
            data_classes = ", ".join(breach.get("DataClasses", []))
            
            table.add_row(name, date, account_count, data_classes)
            
        console.print(table)
        
        console.print("\n[yellow]Recommendation:[/yellow] Consider changing your passwords for these services and any other services where you've used the same password.")
    
    def display_file_summary(self, results):
        """Display a summary of results from checking multiple emails."""
        if not results:
            return
            
        # Count emails in different categories
        total = len(results)
        breached = 0
        clean = 0
        error = 0
        
        # Count breaches per email
        breach_counts = {}
        
        for email, breaches in results.items():
            if breaches is None:
                error += 1
            elif not breaches:
                clean += 1
            else:
                breached += 1
                breach_counts[email] = len(breaches)
        
        # Display summary
        console.print("\n[bold cyan]File Check Summary[/bold cyan]")
        console.print(f"Total emails checked: [bold]{total}[/bold]")
        console.print(f"Clean emails: [bold green]{clean}[/bold green]")
        console.print(f"Breached emails: [bold red]{breached}[/bold red]")
        if error > 0:
            console.print(f"Emails with errors: [bold yellow]{error}[/bold yellow]")
            
        # Display breached emails in a table if any
        if breached > 0:
            console.print("\n[bold]Breached Email Addresses:[/bold]")
            table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
            table.add_column("Email", style="cyan")
            table.add_column("Number of Breaches", style="red", justify="right")
            
            for email, count in sorted(breach_counts.items(), key=lambda x: x[1], reverse=True):
                table.add_row(email, str(count))
                
            console.print(table)

    def display_password_results(self, count):
        """Display the results of a password check."""
        if count is None:
            return
            
        if count == 0:
            console.print(Panel(
                "[bold green]Good news![/bold green] This password was not found in any known data breaches.",
                title="Password Check Results",
                border_style="green"
            ))
        else:
            console.print(Panel(
                f"[bold red]Warning![/bold red] This password was found in [bold red]{count:,}[/bold red] data breaches.",
                title="Password Check Results",
                border_style="red"
            ))
            console.print("\n[yellow]Recommendation:[/yellow] This password has been exposed in data breaches and should not be used. Please choose a different password.")

    def display_breach_details(self, breach):
        """Display detailed information about a specific breach."""
        if breach is None:
            return
            
        # Create a formatted panel for breach information
        title = Text(f"Breach Details: {breach.get('Name', 'Unknown')}")
        breach_panel = Panel(
            f"""
[bold]Title:[/bold] {breach.get('Title', 'Unknown')}
[bold]Breach Date:[/bold] {breach.get('BreachDate', 'Unknown')}
[bold]Added Date:[/bold] {breach.get('AddedDate', 'Unknown')}
[bold]Compromised Accounts:[/bold] {breach.get('PwnCount', 0):,}
[bold]Verified:[/bold] {'Yes' if breach.get('IsVerified', False) else 'No'}
[bold]Sensitive:[/bold] {'Yes' if breach.get('IsSensitive', False) else 'No'}
[bold]Fabricated:[/bold] {'Yes' if breach.get('IsFabricated', False) else 'No'}
[bold]Retired:[/bold] {'Yes' if breach.get('IsRetired', False) else 'No'}
[bold]Spam List:[/bold] {'Yes' if breach.get('IsSpamList', False) else 'No'}
[bold]Description:[/bold] {breach.get('Description', 'No description available')}
            """,
            title=title,
            border_style="cyan"
        )
        
        console.print(breach_panel)
        
        # Display the compromised data classes
        data_classes = breach.get('DataClasses', [])
        if data_classes:
            table = Table(title="Compromised Data Types", show_header=True, box=box.SIMPLE)
            table.add_column("Data Type", style="yellow")
            
            for data_class in data_classes:
                table.add_row(data_class)
                
            console.print(table)


def main():
    """Main function to parse arguments and run the HIBP checker."""
    parser = argparse.ArgumentParser(description="Check for compromised accounts using the Have I Been Pwned API.")
    
    parser.add_argument("--key", "-k", help="HIBP API key (required for email checks)")
    parser.add_argument("--no-rate-limit", action="store_true", help="Disable rate limiting (use with caution)")
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Email check command
    email_parser = subparsers.add_parser("email", help="Check if an email has been compromised")
    email_parser.add_argument("email", help="Email address to check")
    
    # Password check command
    password_parser = subparsers.add_parser("password", help="Check if a password has been compromised")
    password_parser.add_argument("password", help="Password to check")
    
    # Breach details command
    breach_parser = subparsers.add_parser("breach", help="Get details about a specific breach")
    breach_parser.add_argument("name", help="Name of the breach to look up")
    
    # File check command
    file_parser = subparsers.add_parser("file", help="Check multiple email addresses from a file")
    file_parser.add_argument("file", help="Path to file containing email addresses (one per line)")
    file_parser.add_argument("--output", "-o", help="Save results to specified file")
    file_parser.add_argument("--summary", "-s", action="store_true", help="Show only summary after completion")
    
    args = parser.parse_args()
    
    # Display banner
    console.print(Panel.fit(
        "[bold cyan]HIBP Checker[/bold cyan] - A tool to check if your accounts have been compromised",
        border_style="blue"
    ))
    
    # Create the HIBP checker with rate limiting (unless disabled)
    checker = HIBPChecker(api_key=args.key, rate_limit=not args.no_rate_limit)
    
    if args.command == "email":
        breaches = checker.check_email(args.email)
        checker.display_email_results(args.email, breaches)
        
    elif args.command == "password":
        count = checker.check_password(args.password)
        checker.display_password_results(count)
        
    elif args.command == "breach":
        breach = checker.get_breach_details(args.name)
        checker.display_breach_details(breach)
        
    elif args.command == "file":
        if not args.key:
            console.print("[bold red]Error:[/bold red] API key is required for checking emails from a file.", style="red")
            return 1
            
        results = checker.check_emails_from_file(args.file, args.output)
        
        # Display summary of the results
        if results:
            checker.display_file_summary(results)
        
    else:
        parser.print_help()
        return 1
        
    return 0


if __name__ == "__main__":
    sys.exit(main())
