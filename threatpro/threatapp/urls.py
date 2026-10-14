"""
URL configuration for threatpro project.
"""

from django.urls import path

from .views import (
    add_threat,
    admin_dashboard,
    admin_view,
    check_reputation,
    dashboard,
    delete_threat,
    delete_user,
    detailed_log_analysis,
    enquiry_list,
    index,
    log_analysis_report,
    log_details,
    login_view,
    logout_view,
    register_view,
    report_incident,
    threat_frequency_chart,
    threat_list,
    update_threat,
    upload_log_file,
    user_list_view,
)

urlpatterns = [
    path("", index, name="index"),
    path("dashboard", dashboard, name="dashboard"),
    path("index", index, name="index"),
    path("admin_dashboard", admin_dashboard, name="admin_dashboard"),
    path("admin_view", admin_view, name="admin_view"),
    path("register", register_view, name="register"),
    path("login", login_view, name="login"),
    path("logout", logout_view, name="logout"),
    path("upload_log_file/", upload_log_file, name="upload_log_file"),
    path("log_analysis_report/", log_analysis_report, name="log_analysis_report"),
    path("threat-chart/<int:log_id>/", threat_frequency_chart, name="threat_frequency_chart"),
    path("check_reputation", check_reputation, name="check_reputation"),
    path("report-incident/", report_incident, name="report_incident"),
    path("detailed-log/", detailed_log_analysis, name="detailed_log"),
    path("log_details", log_details, name="log_details"),
    path("threat_list", threat_list, name="threat_list"),
    path("add_threat", add_threat, name="add_threat"),
    path("threats/update/<int:threat_id>/", update_threat, name="update_threat"),
    path("threats/delete/<int:threat_id>/", delete_threat, name="delete_threat"),
    path("user_list_view", user_list_view, name="user_list_view"),
    path("delete_user/<int:id>", delete_user, name="delete_user"),
    path("admin-log-report", log_analysis_report, name="log_analysis_report"),
    path("enquiry_list", enquiry_list, name="enquiry_list"),
]
