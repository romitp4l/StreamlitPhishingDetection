import pandas as pd

from src.frontend.streamlit_view import phising_url_view
data = pd.read_csv('data/dataset.csv')

if __name__ == "__main__":
  phising_url_view(data)