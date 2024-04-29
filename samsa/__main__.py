from .settings import settings


if __name__ == "__main__":
    import uvicorn

    logging_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "handlers": {
            "default": {
                "class": "logging.StreamHandler",
                "formatter": "default",
                "stream": "ext://sys.stderr"
            },
            "access": {
                "class": "logging.StreamHandler",
                "formatter": "access",
                "stream": "ext://sys.stdout"
            },
        },
        "formatters": {
            "default": {
                "()": "uvicorn.logging.DefaultFormatter",
                "format": "%(asctime)s - %(levelname)s - %(message)s",
            },
            "access": {
                "()": "uvicorn.logging.AccessFormatter",
                "format": '%(asctime)s - "%(request_line)s" %(status_code)s',
            }
        },
        "loggers": {
            "uvicorn.error": {
                "level": "INFO",
                "handlers": ["default"],
                "propagate": False,
            },
            "uvicorn.access": {
                "level": "INFO",
                "handlers": ["access"],
                "propagate": False,
            }
        }
    }

    uvicorn.run(
        "samsa.app:app",
        host="0.0.0.0", port=8000,
        reload=settings.debug,
        log_level="debug" if settings.debug else "info",
        log_config=logging_config
    )
