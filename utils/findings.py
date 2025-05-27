# utils/findings.py

from enum import Enum

class Severity(Enum):
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1

    def __str__(self):
        return self.name

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented

class Finding:
    """Represents a single vulnerability or misconfiguration finding."""
    def __init__(self, check_type: str, severity: Severity, title: str, description: str, recommendation: str = None, details: str = None):
        self.check_type = check_type
        self.severity = severity
        self.title = title
        self.description = description
        self.recommendation = recommendation
        self.details = details

    def __str__(self):
        details_str = f"\n    Details: {self.details}" if self.details else ""
        recommendation_str = f"\n    Recommendation: {self.recommendation}" if self.recommendation else ""
        return (
            f"  Severity: {self.severity}\n"
            f"  Check Type: {self.check_type}\n"
            f"  Title: {self.title}\n"
            f"  Description: {self.description}{details_str}{recommendation_str}\n"
        )


class FindingsCollector:
    """Collects and manages all findings."""
    _instance = None
    _findings = []

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(FindingsCollector, cls).__new__(cls)
            cls._findings = []
        return cls._instance

    @classmethod
    def add_finding(cls, check_type: str, severity: Severity, title: str, description: str, recommendation: str = None, details: str = None):
        """Adds a new finding to the collection."""
        finding = Finding(check_type, severity, title, description, recommendation, details)
        cls._findings.append(finding)

    @classmethod
    def get_findings(cls):
        """Returns all collected findings."""
        return cls._findings

    @classmethod
    def print_summary(cls):
        """Prints a prioritized summary of all findings."""
        if not cls._findings:
            print("\n[+] No significant privilege escalation opportunities found during the scan. (Good!)")
            return

        # Sort findings by severity (highest first) and then by check type
        sorted_findings = sorted(cls._findings, key=lambda f: (f.severity, f.check_type), reverse=True)

        print("\n" + "=" * 50)
        print("    PRIVILEGE ESCALATION OPPORTUNITIES SUMMARY  ")
        print("=" * 50)

        current_severity = None
        for i, finding in enumerate(sorted_findings):
            if finding.severity != current_severity:
                current_severity = finding.severity
                print(f"\n--- {current_severity} SEVERITY FINDINGS ---")

            print(f"\nOpportunity {i + 1}:")
            print(f"  Title: {finding.title}")
            print(f"  Check Type: {finding.check_type}")
            print(f"  Description: {finding.description}")
            if finding.details:
                print(f"  Details: {finding.details}")
            if finding.recommendation:
                print(f"  Recommendation: {finding.recommendation}")
            print("-" * 30) # Separator for individual opportunities
        
        print("\n" + "=" * 50)
        print("    END OF SUMMARY  ")
        print("=" * 50)

# Initialize the collector (singleton pattern)
findings_collector = FindingsCollector()