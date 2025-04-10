from mcp import server
from mcp.server.fastmcp import FastMCP
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from dotenv import load_dotenv
import os
import sys
from typing import Any, List, Dict, Optional, Union
import datetime
import anyio

# === Load environment variables ===
load_dotenv()

# === Define logging placeholders ===
def log_debug(message: str):
    """Log debug messages to stderr to avoid MCP protocol conflicts."""
    print(f"DEBUG: {message}", file=sys.stderr)

def log_memory_usage():
    """Log memory usage to stderr."""
    print("DEBUG: Memory usage check placeholder.", file=sys.stderr)

# === Config ===
OTX_API_KEY = os.getenv("OTX_API_KEY")
otx = OTXv2(OTX_API_KEY)

mcp = FastMCP("otx")

@mcp.tool()
async def search_indicators(keyword: str, page: int = 1, limit: int = 10) -> Any:
    """Search OTX for pulses matching the keyword (paginated).

    This tool searches the OTX platform for pulses matching the provided keyword,
    allowing direct control over pagination via `page` and `limit` parameters.
    It makes a single API call for the requested page.

    Args:
        keyword: The search term to look for in pulses.
        page: The page number of results to retrieve (default: 1).
        limit: The maximum number of results per page (default: 10).

    Returns:
        The raw API response dictionary for the requested page, including 'results',
        'count', 'next', and 'previous' fields, allowing the client to handle further pagination.
    """
    try:
        # Manually construct the URL using the base path and parameters
        search_url = otx.create_url("/api/v1/search/pulses", q=keyword, page=page, limit=limit)
        log_debug(f"Calling paginated pulse search: {search_url}")
        # Use the lower-level get() method, run in a thread to avoid blocking
        response = await anyio.to_thread.run_sync(otx.get, search_url)
        log_memory_usage() # Keep memory log if useful
        return response
    except Exception as e:
        log_debug(f"Error in search_indicators: {e}")
        return {"error": f"Error executing tool search_indicators: {str(e)}"}

@mcp.tool()
async def get_pulse(pulse_id: str) -> Any:
    """Get full details of a Pulse using its ID, minus indicators.
    
    This tool retrieves comprehensive information about a specific pulse by its ID.
    It returns all metadata about the pulse but excludes the indicators to keep the response size manageable.
    
    Use this tool when:
    - You have a pulse ID and want to get detailed information about it
    - You need to understand the context and metadata of a specific threat intelligence report
    - You want to verify the details of a pulse before working with it
    
    Args:
        pulse_id: The unique identifier of the pulse (24-character hex string)
    
    Returns:
        A dictionary containing the pulse details including name, description, author,
        creation date, tags, and other metadata (but not the indicators themselves).
    """
    try:
        log_debug(f"Calling get_pulse with pulse_id={pulse_id}")
        # Run the potentially blocking library call in a thread
        pulse = await anyio.to_thread.run_sync(otx.get_pulse_details, pulse_id)
        pulse.pop("indicators", None)  # Remove bulky field as intended
        log_memory_usage()
        return pulse
    except Exception as e:
        log_debug(f"Error in get_pulse: {e}")
        return {"error": f"Error executing tool get_pulse: {str(e)}"}

@mcp.tool()
async def extract_indicators_from_pulse(pulse_id: str, page: int = 1, limit: int = 20) -> Any:
    """Extract a paginated list of indicators from a given Pulse ID.

    This tool retrieves indicators (IOCs) contained within a specific pulse,
    allowing direct control over pagination via `page` and `limit` parameters.

    Use this tool when:
    - You need to extract specific indicators from a pulse for analysis
    - You want to identify the IOCs associated with a particular threat
    - You're building a collection of indicators for threat hunting or detection
    - A pulse contains too many indicators to retrieve all at once

    Args:
        pulse_id: The unique identifier of the pulse (24-character hex string).
        page: The page number of indicators to retrieve (default: 1).
        limit: The maximum number of indicators per page (default: 20).

    Returns:
        The raw API response dictionary for the requested page of indicators,
        including 'results', 'count', 'next', and 'previous' fields.
    """
    try:
        # Construct the specific URL for pulse indicators with pagination
        indicators_url = otx.create_url(f"/api/v1/pulses/{pulse_id}/indicators", page=page, limit=limit)
        log_debug(f"Calling paginated pulse indicators: {indicators_url}")
        # Use the lower-level get() method, run in a thread to avoid blocking
        response = await anyio.to_thread.run_sync(otx.get, indicators_url)
        log_memory_usage()
        return response
    except Exception as e:
        log_debug(f"Error in extract_indicators_from_pulse: {e}")
        return {"error": f"Error executing tool extract_indicators_from_pulse: {str(e)}"}

@mcp.tool()
async def get_indicator_details(indicator_type: str, indicator: str, section: str = "general") -> Any:
    """Get detailed information about a specific indicator.
    
    This tool retrieves detailed information about a specific indicator from OTX.
    It can focus on a particular section of information (e.g., general, reputation, geo, etc.)
    depending on the indicator type.
    
    Use this tool when:
    - You need detailed information about a specific indicator (IP, domain, URL, etc.)
    - You want to understand the reputation or characteristics of an indicator
    - You're investigating a potential threat and need context about specific IOCs
    
    Args:
        indicator_type: Type of indicator (e.g., 'IPv4', 'domain', 'url', 'email', 'hash')
        indicator: The indicator value (e.g., '8.8.8.8', 'example.com', 'https://malicious.com')
        section: Section of details to retrieve (default: 'general')
                 Other sections may include 'reputation', 'geo', 'passive_dns', etc.
                 Available sections depend on the indicator type.
    
    Returns:
        A dictionary containing detailed information about the indicator,
        focused on the requested section.
    """
    try:
        # Convert string to IndicatorTypes enum if needed
        enum_type = None
        if isinstance(indicator_type, str):
            enum_type = getattr(IndicatorTypes, indicator_type.upper(), None)
            if enum_type is None:
                return {"error": f"Invalid indicator type string: {indicator_type}"}
        
        # Run the potentially blocking library call in a thread
        details = await anyio.to_thread.run_sync(otx.get_indicator_details_by_section, enum_type, indicator, section)
        log_memory_usage()
        return details
    except Exception as e:
        log_debug(f"Error in get_indicator_details: {e}")
        return {"error": f"Error executing tool get_indicator_details: {str(e)}"}

@mcp.tool()
async def get_indicator_details_full(indicator_type: str, indicator: str) -> Any:
    """Get all available details about a specific indicator.
    
    This tool retrieves comprehensive information about a specific indicator from OTX,
    including all available sections of data. This provides the most complete picture
    of an indicator's characteristics, reputation, and associated threats.
    
    Use this tool when:
    - You need a complete analysis of a specific indicator
    - You want to gather all available intelligence about a potential threat
    - You're performing detailed threat research on a specific IOC
    
    Args:
        indicator_type: Type of indicator (e.g., 'IPv4', 'domain', 'url', 'email', 'hash')
        indicator: The indicator value (e.g., '8.8.8.8', 'example.com', 'https://malicious.com')
    
    Returns:
        A dictionary with sections as keys and the corresponding detailed information
        for each section as values. This provides a complete picture of the indicator.
    """
    try:
        # Convert string to IndicatorTypes enum if needed
        enum_type = None
        if isinstance(indicator_type, str):
            enum_type = getattr(IndicatorTypes, indicator_type.upper(), None)
            if enum_type is None:
                return {"error": f"Invalid indicator type string: {indicator_type}"}
        
        # Run the potentially blocking library call in a thread
        details = await anyio.to_thread.run_sync(otx.get_indicator_details_full, enum_type, indicator)
        log_memory_usage()
        return details
    except Exception as e:
        log_debug(f"Error in get_indicator_details_full: {e}")
        return {"error": f"Error executing tool get_indicator_details_full: {str(e)}"}

@mcp.tool()
async def search_users(query: str, max_results: int = 25) -> Any:
    """Search for users in OTX.
    
    This tool searches the OTX platform for users matching the provided query.
    It's useful for finding researchers, analysts, or organizations that publish
    threat intelligence on OTX.
    
    Use this tool when:
    - You want to find specific users or organizations on OTX
    - You're looking for researchers who publish on particular threat topics
    - You want to discover new sources of threat intelligence
    
    Args:
        query: Search query to find users (e.g., "AlienVault", "researcher name")
        max_results: Maximum number of results to return (default: 25)
    
    Returns:
        A dictionary containing search results with users matching the query.
        Each user entry includes username, full name, and other profile information.
    """
    try:
        # Run the potentially blocking library call in a thread
        results = await anyio.to_thread.run_sync(otx.search_users, query, max_results=max_results)
        log_memory_usage()
        return results
    except Exception as e:
        log_debug(f"Error in search_users: {e}")
        return {"error": f"Error executing tool search_users: {str(e)}"}

@mcp.tool()
async def get_user(username: str, detailed: bool = True) -> Any:
    """Get information about a specific user.
    
    This tool retrieves detailed information about a specific OTX user,
    including their profile, statistics, and recent activity.
    
    Use this tool when:
    - You want to learn more about a specific user or organization
    - You need to verify a user's identity or credentials
    - You're evaluating a user as a potential source of threat intelligence
    
    Args:
        username: Username to look up (e.g., "AlienVault", "researcher_name")
        detailed: Whether to return detailed information (default: True)
                 If False, returns only basic profile information.
    
    Returns:
        A dictionary containing user information, including profile details,
        statistics, and recent activity if detailed=True.
    """
    try:
        # Run the potentially blocking library call in a thread
        user_info = await anyio.to_thread.run_sync(otx.get_user, username, detailed=detailed)
        log_memory_usage()
        return user_info
    except Exception as e:
        log_debug(f"Error in get_user: {e}")
        return {"error": f"Error executing tool get_user: {str(e)}"}

@mcp.tool()
async def get_user_pulses(username: str, query: Optional[str] = None, max_items: int = 200) -> Any:
    """Get pulses created by a specific user.
    
    This tool retrieves all pulses created by a specific user, optionally filtered
    by a search query. It's useful for exploring a user's threat intelligence contributions.
    
    Use this tool when:
    - You want to explore all threat intelligence published by a specific user
    - You're researching a particular threat and know a user who has published on it
    - You want to discover new threat intelligence from trusted sources
    
    Args:
        username: Username to get pulses for (e.g., "AlienVault", "researcher_name")
        query: Optional search query to filter pulses (e.g., "ransomware", "APT")
        max_items: Maximum number of items to return (default: 200)
    
    Returns:
        A list of pulses created by the specified user, optionally filtered by the query.
        Each pulse includes metadata like name, description, and creation date.
    """
    try:
        # Run the potentially blocking library call in a thread
        pulses = await anyio.to_thread.run_sync(otx.get_user_pulses, username, query=query, max_items=max_items)
        log_memory_usage()
        return pulses
    except Exception as e:
        log_debug(f"Error in get_user_pulses: {e}")
        return {"error": f"Error executing tool get_user_pulses: {str(e)}"}

@mcp.tool()
async def get_my_pulses(query: Optional[str] = None, max_items: int = 200) -> Any:
    """Get pulses created by the authenticated user.
    
    This tool retrieves all pulses created by the currently authenticated user,
    optionally filtered by a search query. It's useful for managing your own
    threat intelligence contributions.
    
    Use this tool when:
    - You want to review your own published threat intelligence
    - You need to find a specific pulse you created
    - You're managing your threat intelligence library
    
    Args:
        query: Optional search query to filter pulses (e.g., "ransomware", "APT")
        max_items: Maximum number of items to return (default: 200)
    
    Returns:
        A list of pulses created by the authenticated user, optionally filtered by the query.
        Each pulse includes metadata like name, description, and creation date.
    """
    try:
        # Run the potentially blocking library call in a thread
        pulses = await anyio.to_thread.run_sync(otx.get_my_pulses, query=query, max_items=max_items)
        log_memory_usage()
        return pulses
    except Exception as e:
        log_debug(f"Error in get_my_pulses: {e}")
        return {"error": f"Error executing tool get_my_pulses: {str(e)}"}

@mcp.tool()
async def follow_user(username: str) -> Any:
    """Follow a user to receive notifications about their activities.
    
    This tool allows you to follow a specific user on OTX, which will notify you
    when they publish new pulses or make other significant activities.
    
    Use this tool when:
    - You want to stay updated on a specific user's threat intelligence
    - You've identified a valuable source of threat intelligence
    - You want to build a network of trusted intelligence sources
    
    Args:
        username: Username to follow (e.g., "AlienVault", "researcher_name")
    
    Returns:
        A dictionary indicating the success or failure of the follow operation.
    """
    try:
        # Run the potentially blocking library call in a thread
        result = await anyio.to_thread.run_sync(otx.follow_user, username)
        log_memory_usage()
        return result
    except Exception as e:
        log_debug(f"Error in follow_user: {e}")
        return {"error": f"Error executing tool follow_user: {str(e)}"}

@mcp.tool()
async def unfollow_user(username: str) -> Any:
    """Unfollow a user to stop receiving notifications about their activities.
    
    This tool allows you to unfollow a user on OTX, which will stop notifications
    about their activities.
    
    Use this tool when:
    - You no longer want to receive notifications from a specific user
    - You're cleaning up your notification preferences
    - You want to reduce notification noise
    
    Args:
        username: Username to unfollow (e.g., "AlienVault", "researcher_name")
    
    Returns:
        A dictionary indicating the success or failure of the unfollow operation.
    """
    try:
        # Run the potentially blocking library call in a thread
        result = await anyio.to_thread.run_sync(otx.unfollow_user, username)
        log_memory_usage()
        return result
    except Exception as e:
        log_debug(f"Error in unfollow_user: {e}")
        return {"error": f"Error executing tool unfollow_user: {str(e)}"}

@mcp.tool()
async def subscribe_to_pulse(pulse_id: str) -> Any:
    """Subscribe to a pulse to receive updates.
    
    This tool allows you to subscribe to a specific pulse, which will notify you
    when the pulse is updated or when new related information becomes available.
    
    Use this tool when:
    - You want to stay updated on a specific threat intelligence report
    - You're tracking a particular threat or campaign
    - You want to ensure you don't miss updates to important intelligence
    
    Args:
        pulse_id: ID of the pulse to subscribe to (24-character hex string)
    
    Returns:
        A dictionary indicating the success or failure of the subscription operation.
    """
    try:
        # Run the potentially blocking library call in a thread
        result = await anyio.to_thread.run_sync(otx.subscribe_to_pulse, pulse_id)
        log_memory_usage()
        return result
    except Exception as e:
        log_debug(f"Error in subscribe_to_pulse: {e}")
        return {"error": f"Error executing tool subscribe_to_pulse: {str(e)}"}

@mcp.tool()
async def unsubscribe_from_pulse(pulse_id: str) -> Any:
    """Unsubscribe from a pulse to stop receiving updates.
    
    This tool allows you to unsubscribe from a pulse, which will stop notifications
    about updates to that pulse.
    
    Use this tool when:
    - You no longer want to receive updates about a specific pulse
    - You're cleaning up your subscription list
    - You want to reduce notification noise
    
    Args:
        pulse_id: ID of the pulse to unsubscribe from (24-character hex string)
    
    Returns:
        A dictionary indicating the success or failure of the unsubscription operation.
    """
    try:
        # Run the potentially blocking library call in a thread
        result = await anyio.to_thread.run_sync(otx.unsubscribe_from_pulse, pulse_id)
        log_memory_usage()
        return result
    except Exception as e:
        log_debug(f"Error in unsubscribe_from_pulse: {e}")
        return {"error": f"Error executing tool unsubscribe_from_pulse: {str(e)}"}

@mcp.tool()
async def create_pulse(
    name: str,
    description: str = "",
    public: bool = True,
    tlp: str = "green",
    tags: List[str] = None,
    references: List[str] = None,
    indicators: List[Dict] = None,
    group_ids: List[int] = None,
    adversary: str = None,
    targeted_countries: List[str] = None,
    industries: List[str] = None,
    malware_families: List[str] = None,
    attack_ids: List[str] = None
) -> Any:
    """Create a new pulse with threat intelligence information.
    
    This tool allows you to create a new pulse (threat intelligence report) on OTX,
    which can include indicators, descriptions, tags, and other metadata.
    
    Use this tool when:
    - You want to share threat intelligence with the OTX community
    - You've discovered new indicators or threats that should be documented
    - You're creating a structured report about a security incident
    
    Args:
        name: Name of the pulse (required, 5-64 characters)
        description: Detailed description of the threat (optional)
        public: Whether the pulse is public (default: True)
               If False, only you and users you explicitly share with can see it
        tlp: Traffic Light Protocol level (default: "green")
             Options: "red", "amber", "green", "white"
             Note: "red" and "amber" require public=False
        tags: List of tags to categorize the pulse (optional)
        references: List of references (URLs, documents) (optional)
        indicators: List of indicator dictionaries (optional)
                   Each indicator should have "indicator" and "type" fields
                   Example: [{"indicator": "8.8.8.8", "type": "IPv4"}]
        group_ids: List of group IDs to add the pulse to (optional)
        adversary: Name of adversary related to the pulse (optional)
        targeted_countries: List of targeted countries (optional)
                           Can use country names or ISO 3166 codes
        industries: List of industries related to the pulse (optional)
        malware_families: List of malware families related to the pulse (optional)
        attack_ids: List of MITRE ATT&CK IDs related to the pulse (optional)
    
    Returns:
        A dictionary containing the created pulse information, including its ID.
    """
    try:
        # Prepare the pulse data dictionary
        pulse_data = {
            "name": name,
            "description": description,
            "public": public,
            "TLP": tlp,
            "tags": tags or [],
            "references": references or [],
            "indicators": indicators or [],
            "group_ids": group_ids or [],
            "adversary": adversary,
            "targeted_countries": targeted_countries or [],
            "industries": industries or [],
            "malware_families": malware_families or [],
            "attack_ids": attack_ids or []
        }
        
        # Run the potentially blocking library call (otx.create_pulse uses otx.post) in a thread
        # Note: We need to pass the function and its arguments correctly to run_sync
        created_pulse = await anyio.to_thread.run_sync(otx.create_pulse, **pulse_data)
        log_memory_usage()
        return created_pulse
    except Exception as e:
        log_debug(f"Error in create_pulse: {e}")
        return {"error": f"Error executing tool create_pulse: {str(e)}"}

@mcp.tool()
async def validate_indicator(indicator_type: str, indicator: str, description: str = "") -> Any:
    """Validate an indicator before adding it to a pulse.
    
    This tool validates an indicator to ensure it meets OTX's requirements before
    adding it to a pulse. It's a good practice to validate indicators before
    creating a pulse to avoid errors.
    
    Use this tool when:
    - You're preparing to create a pulse with indicators
    - You want to ensure an indicator is properly formatted
    - You need to verify that an indicator type is supported
    
    Args:
        indicator_type: Type of indicator (e.g., 'IPv4', 'domain', 'url', 'email', 'hash')
        indicator: The indicator value (e.g., '8.8.8.8', 'example.com', 'https://malicious.com')
        description: Optional description of the indicator
    
    Returns:
        A dictionary containing validation results, indicating whether the indicator
        is valid and any issues that were found.
    """
    try:
        # Convert string to IndicatorTypes enum if needed
        enum_type = None
        if isinstance(indicator_type, str):
            enum_type = getattr(IndicatorTypes, indicator_type.upper(), None)
            if enum_type is None:
                return {"error": f"Invalid indicator type string: {indicator_type}"}
        
        # Run the potentially blocking library call (otx.validate_indicator uses otx.post) in a thread
        validation_result = await anyio.to_thread.run_sync(otx.validate_indicator, enum_type, indicator, description)
        log_memory_usage()
        return validation_result
    except Exception as e:
        log_debug(f"Error in validate_indicator: {e}")
        return {"error": f"Error executing tool validate_indicator: {str(e)}"}

@mcp.tool()
async def submit_url(url: str) -> Any:
    """Submit a URL for analysis.
    
    This tool submits a URL to OTX for analysis, which can help identify
    malicious websites, phishing attempts, or other threats.
    
    Use this tool when:
    - You've discovered a suspicious URL and want it analyzed
    - You're investigating a potential phishing campaign
    - You need to verify if a website is malicious
    
    Args:
        url: URL to submit for analysis (e.g., "https://malicious-example.com")
    
    Returns:
        A dictionary containing the submission status and analysis results.
        Note that analysis may take some time to complete.
    """
    try:
        # Run the potentially blocking library call (otx.submit_url uses otx.post) in a thread
        submission_status = await anyio.to_thread.run_sync(otx.submit_url, url)
        log_memory_usage()
        return submission_status
    except Exception as e:
        log_debug(f"Error in submit_url: {e}")
        return {"error": f"Error executing tool submit_url: {str(e)}"}

@mcp.tool()
async def submit_urls(urls: List[str]) -> Any:
    """Submit multiple URLs for analysis.
    
    This tool submits multiple URLs to OTX for batch analysis, which is more
    efficient than submitting them one by one.
    
    Use this tool when:
    - You have multiple suspicious URLs to analyze
    - You're investigating a campaign with multiple related URLs
    - You need to verify multiple websites at once
    
    Args:
        urls: List of URLs to submit for analysis
              Example: ["https://malicious1.com", "https://malicious2.com"]
    
    Returns:
        A dictionary containing the submission status and analysis results.
        Note that analysis may take some time to complete.
    """
    try:
        # Run the potentially blocking library call (otx.submit_urls uses otx.post) in a thread
        submission_status = await anyio.to_thread.run_sync(otx.submit_urls, urls)
        log_memory_usage()
        return submission_status
    except Exception as e:
        log_debug(f"Error in submit_urls: {e}")
        return {"error": f"Error executing tool submit_urls: {str(e)}"}

@mcp.tool()
async def get_recent_events(timestamp: Optional[str] = None, limit: int = 50) -> Any:
    """Get recent events/activities from OTX.
    
    This tool retrieves recent events and activities from OTX, such as new pulses,
    subscriptions, and other user actions. It's useful for staying updated on
    the latest threat intelligence.
    
    Use this tool when:
    - You want to see the latest activity on OTX
    - You're monitoring for new threat intelligence
    - You need to track changes to pulses you're interested in
    
    Args:
        timestamp: ISO formatted datetime string to restrict results
                  (not older than timestamp). If not provided, defaults to 24 hours ago.
        limit: Maximum number of results to return (default: 50)
    
    Returns:
        A list of event dictionaries, each describing an activity on OTX,
        including the type of event, timestamp, and related objects.
    """
    try:
        # If no timestamp provided, use 24 hours ago
        final_timestamp = timestamp
        if final_timestamp is None:
            final_timestamp = (datetime.datetime.now() - datetime.timedelta(days=1)).isoformat()
        
        # Run the potentially blocking library call (otx.getevents_since uses otx.get) in a thread
        events = await anyio.to_thread.run_sync(otx.getevents_since, timestamp=final_timestamp, limit=limit)
        log_memory_usage()
        return events
    except Exception as e:
        log_debug(f"Error in get_recent_events: {e}")
        return {"error": f"Error executing tool get_recent_events: {str(e)}"}

@mcp.tool()
async def get_subscribed_pulses(modified_since: Optional[str] = None, author_name: Optional[str] = None, limit: int = 50) -> Any:
    """Get pulses the user is subscribed to.
    
    This tool retrieves pulses that the authenticated user is subscribed to,
    optionally filtered by modification date or author.
    
    Use this tool when:
    - You want to see all pulses you're subscribed to
    - You're checking for updates to pulses you follow
    - You need to find pulses from specific authors you subscribe to
    
    Args:
        modified_since: ISO formatted datetime string to restrict results
                       (not older than timestamp)
        author_name: Filter by author name (e.g., "AlienVault", "researcher_name")
        limit: Maximum number of results to return (default: 50)
    
    Returns:
        A list of pulse dictionaries, each containing metadata about a pulse
        the user is subscribed to, optionally filtered by the provided criteria.
    """
    try:
        # Run the potentially blocking library call (otx.getall uses otx.get) in a thread
        pulses = await anyio.to_thread.run_sync(otx.getall, modified_since=modified_since, author_name=author_name, limit=limit)
        log_memory_usage()
        return pulses
    except Exception as e:
        log_debug(f"Error in get_subscribed_pulses: {e}")
        return {"error": f"Error executing tool get_subscribed_pulses: {str(e)}"}

mcp.list_resources = lambda: []
mcp.list_prompts = lambda: []

if __name__ == "__main__":
    mcp.run(transport="stdio")
