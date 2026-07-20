from .ui.app import NetzunamiApp
from .auto_index import auto_index


def main():
    auto_index(verbose=False)
    app = NetzunamiApp()
    app.run()


if __name__ == "__main__":
    main()
