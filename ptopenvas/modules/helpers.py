from lxml import etree
import uuid
from typing import List, Tuple, Union
import time

def _ensure_tree(maybe_xml: Union[str, etree._Element]) -> etree._Element:
    """
    Convert XML string to ElementTree if necessary.
    """
    if isinstance(maybe_xml, str):
        return etree.fromstring(maybe_xml.encode())
    return maybe_xml

def _list_port_lists(gmp) -> List[Tuple[str, str, bool]]:
    """
    Return all port lists as a list of tuples: (id, name, predefined_flag)
    """
    root = _ensure_tree(gmp.get_port_lists())
    items = []
    for pl in root.xpath("//port_list"):
        pid = pl.get("id") or pl.findtext("id")
        name = pl.findtext("name") or ""
        predefined_flag = pl.findtext("predefined") == "1"
        items.append((pid, name, predefined_flag))
    return items

def _get_default_portlist_id(gmp, proto: str) -> str:
    """
    Return the ID of the default All TCP or All UDP port list.
    Raises RuntimeError if not found.
    """
    proto = proto.lower()
    defaults = {"tcp": "All IANA assigned TCP", "udp": "All UDP"}
    root = _ensure_tree(gmp.get_port_lists())
    node = root.xpath(f"//port_list[name='{defaults.get(proto, '')}']")
    if not node:
        raise RuntimeError(f"Default port list for {proto} not found")
    return node[0].get("id")

def _create_temp_portlist(gmp, ports: str) -> Tuple[str, str]:
    """
    Create a temporary port list in GVM for a scan.
    ports: string like "22,80,443" or "1000-2000"
    Returns: (portlist_id, name)
    """
    tmp_name = f"pt-{ports}-{time.strftime('%H:%M:%S')}"
    created_xml = gmp.create_port_list(name=tmp_name, port_range=ports)
    root = _ensure_tree(created_xml)
    pid = root.findtext("id") or (root.xpath("//@id")[0] if root.xpath("//@id") else None)
    if not pid:
        raise RuntimeError("Failed to create temporary port list")
    return pid, tmp_name

def _cleanup_portlist(gmp, portlist_id: str) -> None:
    """
    Delete a temporary port list. Ignore errors.
    """
    try:
        gmp.delete_port_list(portlist_id)
    except Exception:
        pass

def get_default_scanner_id(gmp):
    """
    Retrieve the ID of the default OpenVAS scanner to assign tasks to.

    Priority:
      1. Scanner whose name contains "openvas" and status "Alive"
      2. Any scanner whose name contains "openvas" (even if not alive)
      3. Fallback to any alive scanner (if no OpenVAS exists)
      4. Fallback to the first registered scanner

    Args:
        gmp: An authenticated GMP connection object.

    Returns:
        str: The ID of the selected scanner.

    Raises:
        RuntimeError: If no scanners are registered in GVMD.
    """
    root = _ensure_tree(gmp.get_scanners())
    scanners = root.xpath("//scanner")
    if not scanners:
        raise RuntimeError("No scanners registered in gvmd")

    # 1) Alive OpenVAS scanner
    for s in scanners:
        name = (s.findtext("name") or "").lower()
        status = (s.findtext("status") or s.get("status") or "").lower()
        if "openvas" in name and status == "alive":
            return s.get("id") or s.findtext("id")

    # 2) Any OpenVAS scanner (not necessarily alive)
    for s in scanners:
        name = (s.findtext("name") or "").lower()
        if "openvas" in name:
            return s.get("id") or s.findtext("id")

    # 3) Any alive scanner
    for s in scanners:
        status = (s.findtext("status") or s.get("status") or "").lower()
        if status == "alive":
            return s.get("id") or s.findtext("id")

    # 4) Fallback: first scanner
    s = scanners[0]
    return s.get("id") or s.findtext("id")


def wait_for_report(gmp, task_id, timeout=300, interval=5, verbose=False):
    """
    Wait until a report is available for the given task.

    Strategy:
     - Poll gmp.get_task(task_id) and look for report id in common places:
         * .//last_report/id
         * .//report/id
         * .//report (check @id)
     - If task status becomes a finished state (Done/Stopped/Aborted/Failed) but no report id found,
       query gmp.get_reports() and filter for reports whose task/id == task_id and return the newest.
     - After timeout, do a final search in reports and raise RuntimeError if nothing found.

    Args:
        gmp: Authenticated GMP connection object.
        task_id: ID of the task.
        timeout: Seconds to wait before giving up.
        interval: Poll interval in seconds.
        verbose: If True, prints progress messages.

    Returns:
        report_id (str)

    Raises:
        RuntimeError: If no report is found within timeout.
    """
    waited = 0
    finished_states = {"done", "stopped", "aborted", "cancelled", "failed"}
    if verbose:
        print(f"[wait_for_report] waiting for report for task {task_id} (timeout={timeout}s)")

    while waited < timeout:
        task_xml = gmp.get_task(task_id)
        # check several common locations for report id
        report_id = (
            task_xml.findtext(".//last_report/id")
            or task_xml.findtext(".//report/id")
        )

        # sometimes report is present as a <report id="..."> element
        if not report_id:
            report_nodes = task_xml.xpath(".//report")
            if report_nodes:
                # try attribute 'id' first, fallback to child <id>
                first = report_nodes[0]
                report_id = first.get("id") or first.findtext("id")

        status = (task_xml.findtext(".//status") or "").strip().lower()
        if verbose:
            print(f"[wait_for_report] waited={waited}s status='{status}' report_id='{report_id}'")

        if report_id:
            if verbose:
                print(f"[wait_for_report] found report id on task: {report_id}")
            return report_id

        # If the task is finished but no report id on task, search reports list
        if status in finished_states:
            if verbose:
                print(f"[wait_for_report] task in finished state '{status}' but no report on task; searching reports table...")
            # search reports for this task
            candidate = _find_latest_report_for_task(gmp, task_id, verbose=verbose)
            if candidate:
                return candidate
            # else continue waiting a little in case the report is still being generated/attached

        time.sleep(interval)
        waited += interval

    # Final attempt after timeout
    if verbose:
        print(f"[wait_for_report] timeout reached ({timeout}s). final search in reports...")
    candidate = _find_latest_report_for_task(gmp, task_id, verbose=verbose)
    if candidate:
        return candidate

    raise RuntimeError(f"No report found for task {task_id} after waiting {timeout} seconds")


def _find_latest_report_for_task(gmp, task_id, verbose=False):
    """
    Search all reports and return the newest report id for the given task_id, or None.
    Uses gmp.get_reports() and XPath; returns the first match or the newest by creation_time if available.
    """
    reports_xml = gmp.get_reports()
    reports = reports_xml.xpath(f"//report[task/id='{task_id}']")
    if not reports:
        if verbose:
            print(f"[_find_latest_report_for_task] no reports found for task {task_id}")
        return None

    # prefer attribute id, else child <id>; prefer newest by creation_time if present
    def extract_info(rnode):
        rid = rnode.get("id") or rnode.findtext("id")
        # try to get creation time if available (many report formats include it)
        ctime = rnode.findtext("creation_time") or rnode.findtext("report/creation_time") or ""
        return (rid, ctime)

    infos = [extract_info(r) for r in reports]
    # if any creation times present, sort by them (lexicographic ISO-8601 is fine)
    if any(info[1] for info in infos):
        infos = sorted(infos, key=lambda x: x[1] or "", reverse=True)
    else:
        # fallback: return first report node's id
        infos = infos

    chosen = infos[0][0] if infos else None
    if verbose:
        print(f"[_find_latest_report_for_task] candidate reports: {[i[0] for i in infos]}; chosen={chosen}")
    return chosen