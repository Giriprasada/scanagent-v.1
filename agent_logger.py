import logging

class Logger:
    def __init__(self):
        self.logger = logging.getLogger('Agent-Scan-Logger')
        logging.basicConfig(level=logging.INFO,
                                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                                handlers=[
                                    logging.StreamHandler(),
                                    logging.FileHandler('ScanAgent.log', encoding='utf-8')
                                ])

    def get_logger(self):
        """Returns the logger instance."""
        return self.logger
