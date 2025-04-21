# test_dashboard.py
import pytest
from dash.testing.application_runners import import_app
from dash.testing.browser import Browser

def test_detailed_analysis_tab(dash_duo):
    # Import your Dash app
    app = import_app("shiny-app.app")
    dash_duo.start_server(app)
    
    # Wait for app to load
    dash_duo.wait_for_element("#tabs", timeout=10)
    
    # Switch to Detailed Analysis tab
    dash_duo.find_element("#tabs .tab:nth-child(2)").click()
    
    # Verify table exists
    assert dash_duo.find_element("#cve-table"), "Data table not found"
    
    # Test basic rendering
    assert len(dash_duo.find_elements("#cve-table .row")) > 0, "No rows loaded"
    
    # Test sorting (click CVSS column)
    dash_duo.find_element("#cve-table .column-header:nth-child(3)").click()
    first_cvss = float(dash_duo.find_element("#cve-table .row:first-child .cell:nth-child(3)").text)
    assert first_cvss >= 9.0, "Sorting by CVSS failed"
    
    # Test filtering
    filter_input = dash_duo.find_element("#cve-table .column-1 .filter-input")
    filter_input.send_keys("Microsoft")
    dash_duo.wait_for_text_to_equal("#cve-table .row:first-child .cell:nth-child(2)", "Microsoft")