import typing

from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import flow
from mitmproxy import types

def search_body(flow, arg):
    arg = arg.encode()
    if arg in flow.request.content:
        flow.marked = True
    if flow.response and arg in flow.response.content:
        flow.marked = True

def search_method(flow, arg):
    if arg.upper() == flow.request.method:
        flow.marked = True
    if arg == 'g' and flow.request.method != 'GET':
        flow.marked = True

def search_cookies(flow, arg):
    if not flow.request or not flow.response:
        return
    for cookies in [flow.request.cookies, flow.response.cookies]:
        for cook in cookies:
            if arg in cook:
                flow.marked = True
            if arg in cookies[cook]:
                flow.marked = True

def search_headers(flow, arg):
    for head in flow.request.headers:
        if arg in head or arg in flow.request.headers[head]:
            flow.marked = True
    if flow.response:
        for head in flow.response.headers:
            if arg in head or arg in flow.response.headers[head]:
                flow.marked = True

def search_url(flow, arg):
    if arg in flow.request.url:
        flow.marked = True

class Search:
    def __init__(self):
        pass

    @command.command("s.a")
    def all(self, flows: typing.Sequence[flow.Flow], arg: types.CmdArgs) -> None:
        for flow in flows:
            flow.marked = False
            search_method(flow, arg)
            search_url(flow, arg)
            search_headers(flow, arg)
            search_cookies(flow, arg)
            search_body(flow, arg)

    @command.command("s.body")
    def body(self, flows: typing.Sequence[flow.Flow], arg: types.CmdArgs) -> None:
        for flow in flows:
            flow.marked = False
            search_body(flow, arg)

    @command.command("s.cook")
    def cookies(self, flows: typing.Sequence[flow.Flow], arg: types.CmdArgs) -> None:
        for flow in flows:
            flow.marked = False
            search_cookies(flow, arg)

    @command.command("s.url")
    def url(self, flows: typing.Sequence[flow.Flow], arg: types.CmdArgs) -> None:
        for flow in flows:
            flow.marked = False
            search_url(flow, arg)

    @command.command("s.method")
    def method(self, flows: typing.Sequence[flow.Flow], arg: types.CmdArgs) -> None:
        for flow in flows:
            flow.marked = False
            search_method(flow, arg)

    @command.command("s.head")
    def headers(self, flows: typing.Sequence[flow.Flow], arg: types.CmdArgs) -> None:
        for flow in flows:
            flow.marked = False
            search_headers(flow, arg)
