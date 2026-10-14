import base64
import io

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


def generate_severity_chart(labels, values):
    if not labels or not values:
        return None
    fig, ax = plt.subplots()
    colors = ["green" if label == "Low" else "yellow" if label == "Medium" else "red" for label in labels]
    ax.pie(values, labels=labels, autopct="%1.1f%%", startangle=90, colors=colors)
    ax.axis("equal")
    buffer = io.BytesIO()
    plt.savefig(buffer, format="png", bbox_inches="tight")
    buffer.seek(0)
    image_data = base64.b64encode(buffer.getvalue()).decode()
    buffer.close()
    plt.close(fig)
    return image_data


def generate_frequency_chart(labels, counts):
    if not labels or not counts:
        return None
    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.barh(labels, counts, color="#2c3e50")
    ax.set_xlabel("Count")
    ax.set_title("Threat Frequency")
    for bar, count in zip(bars, counts):
        ax.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height() / 2, str(count), va="center")
    plt.tight_layout()
    buffer = io.BytesIO()
    plt.savefig(buffer, format="png", bbox_inches="tight")
    buffer.seek(0)
    image_data = base64.b64encode(buffer.getvalue()).decode()
    buffer.close()
    plt.close(fig)
    return image_data
