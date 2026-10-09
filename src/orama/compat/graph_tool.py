"""Import-free graph-as-tool callable; the caller owns framework registration."""


def graph_tool(name: str, graph: object, *, input_model: type, state_from: object,
               output_key: str, description: str = "Run the native compiled graph.") -> object:
    """Expose one typed request argument without a framework object or scheduler."""
    if (not isinstance(name, str) or not name.isidentifier()
            or not isinstance(output_key, str) or not output_key.strip()
            or not isinstance(input_model, type) or not callable(state_from)):
        raise ValueError("tool name, output key, and state mapper must be explicit")
    if not callable(getattr(graph, "ainvoke", None)):
        raise TypeError("graph must expose ainvoke")

    async def invoke(request: object) -> object:
        """Validate the request, map explicitly, and await the graph's native scheduler."""
        if not isinstance(request, input_model):
            raise TypeError("request must match the tool input model")
        result = await graph.ainvoke(state_from(request))
        if result.status != "done" or result.error is not None:
            raise RuntimeError("graph did not complete successfully")
        if output_key not in result.scratchpad:
            raise RuntimeError(f"graph completed without output key {output_key!r}")
        return result.scratchpad[output_key]

    invoke.__name__ = name
    invoke.__doc__ = description
    invoke.__annotations__ = {"request": input_model, "return": object}
    return invoke
