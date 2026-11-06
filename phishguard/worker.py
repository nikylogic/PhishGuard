"""One background thread that owns the sandbox browser and works through a queue.

Playwright's sync API is not thread-safe, so Flask's request threads never touch
the browser. They submit a job and get a Future back.
"""
import logging
import queue
import threading
from concurrent.futures import Future

from playwright.sync_api import Error as PWError

from .sandbox import Capture, Sandbox

log = logging.getLogger("phishguard.worker")
_STOP = object()


class ScanWorker:
    def __init__(self, sandbox_factory, on_done=None):
        """sandbox_factory() builds a Sandbox inside the worker thread.
        on_done(scan_id, capture) is called on the worker thread after each job."""
        self._factory = sandbox_factory
        self._on_done = on_done
        self._q: queue.Queue = queue.Queue()
        self._thread = threading.Thread(target=self._run, name="pg-sandbox", daemon=True)
        self.sandbox: Sandbox | None = None
        self.ready = threading.Event()
        self.jobs_done = 0

    def start(self):
        self._thread.start()
        return self

    def submit(self, url: str, scan_id) -> Future:
        fut: Future = Future()
        self._q.put((url, scan_id, fut))
        return fut

    def call(self, fn) -> Future:
        """Run fn(sandbox) on the worker thread (used by tests to simulate a crash)."""
        fut: Future = Future()
        self._q.put((fn, None, fut))
        return fut

    def stop(self, timeout=10):
        self._q.put(_STOP)
        self._thread.join(timeout)

    def _run(self):
        self.sandbox = self._factory()
        try:
            self.sandbox.start()
        except Exception:   # noqa: BLE001 - keep the worker alive; ensure() retries per job
            log.exception("sandbox browser failed to start; will retry on first job")
        self.ready.set()
        while True:
            item = self._q.get()
            if item is _STOP:
                break
            target, scan_id, fut = item
            if callable(target):
                try:
                    fut.set_result(target(self.sandbox))
                except Exception as e:   # noqa: BLE001
                    fut.set_exception(e)
                continue
            cap = self._capture_with_retry(target, scan_id)
            self.jobs_done += 1
            if self._on_done:
                try:
                    self._on_done(scan_id, cap)
                except Exception:   # noqa: BLE001
                    log.exception("on_done failed for scan %s", scan_id)
            fut.set_result(cap)
        self.sandbox.close()

    def _capture_with_retry(self, url, scan_id) -> Capture:
        for attempt in (1, 2):
            try:
                return self.sandbox.capture(url, scan_id)
            except PWError as e:
                log.warning("capture attempt %s failed (%s); relaunching browser", attempt, e)
                try:
                    self.sandbox.browser = None
                    self.sandbox.ensure()
                except Exception:   # noqa: BLE001
                    log.exception("browser relaunch failed")
            except Exception as e:   # noqa: BLE001
                log.exception("unexpected capture error")
                return Capture(url=url, final_url=url, status="failed",
                               error=f"Internal error while inspecting: {type(e).__name__}")
        return Capture(url=url, final_url=url, status="failed",
                       error="The sandbox browser crashed twice while opening this link.")
