defmodule Logster.Plugs.Logger do
  @moduledoc """
  A plug for logging request information in the format:

      method=GET path=/articles/some-article format=html controller=HelloPhoenix.ArticleController action=show params={"id":"some-article"} status=200 duration=0.402 state=set

  To use it, just plug it into the desired module.

      plug Logster.Plugs.Logger, log: :debug

  For Phoenix applications, replace `Plug.Logger` with `Logster.Plugs.Logger` in the `endpoint.ex` file:

      # plug Plug.Logger
      plug Logster.Plugs.Logger

  ## Options

    * `:log` - The log level at which this plug should log its request info.
      Default is `:info`.
  """

  require Logger
  alias Plug.Conn

  @default_filter_parameters ~w(password)
  @default_allowed_headers ~w()

  def init(opts) do
    opts
  end

  def call(conn, opts) do
    start_time = current_time()

    Conn.register_before_send(conn, fn conn ->
      Logger.log log_level(conn, opts), fn ->
        formatter = Keyword.get(opts, :formatter, Logster.StringFormatter)
        stop_time = current_time()
        duration = time_diff(start_time, stop_time)
        []
        |> Keyword.put(:method, conn.method)
        |> Keyword.put(:path, conn.request_path)
        |> Keyword.merge(formatted_phoenix_info(conn))
        |> Keyword.put(:params, get_params(conn))
        |> Keyword.put(:status, conn.status)
        |> Keyword.put(:duration, formatted_duration(duration))
        |> Keyword.put(:state, conn.state)
        |> Keyword.merge(response_body(conn))
        |> Keyword.merge(headers(conn.req_headers, Application.get_env(:logster, :allowed_headers, @default_allowed_headers)))
        |> Keyword.merge(Logger.metadata())
        |> formatter.format
      end
      conn
    end)
  end

  defp response_body(conn) do
    content_type_header = List.keyfind(conn.resp_headers, "content-type", 0)
    case Application.get_env(:logster, :log_response, false) do
      true ->
        get_response_body(conn, content_type_header)
      false ->
        []
      desired_content_type ->
        case content_type_header do
          {_, content_type} ->
            if String.starts_with?(content_type, desired_content_type) do
              get_response_body(conn, content_type_header)
            else
              []
            end
          _x -> []
      end
    end
  end

  defp get_response_body(conn, content_type) do
    maximum_size = Application.get_env(:logster, :log_response_limit, 2048)

    if IO.iodata_length(conn.resp_body) > maximum_size do
      [{:resp_body, "[Truncated]"}]
    else
      case content_type do
        {"content-type", "application/json" <> _} ->
          get_json_response_body(conn.resp_body)
        _ ->
          [{:resp_body, conn.resp_body}]
      end
    end
  end

  defp get_json_response_body(body) do
    resp = Poison.decode!(body)
    |> do_filter_params(Application.get_env(:logster, :filter_parameters, @default_filter_parameters))
    |> do_format_values
    [{:resp_body, resp}]
  end

  defp headers(_, []), do: []
  defp headers(conn_headers, allowed_headers) do
    map = conn_headers
    |> Enum.filter(fn({k, _}) -> Enum.member?(allowed_headers, k) end)
    |> Enum.into(%{}, fn {k,v} -> {k,v} end)

    [{:headers, map}]
  end

  defp current_time, do: :erlang.monotonic_time
  defp time_diff(start, stop), do: (stop - start) |> :erlang.convert_time_unit(:native, :micro_seconds)

  defp formatted_duration(duration), do: duration / 1000

  defp formatted_phoenix_info(%{private: %{phoenix_format: format, phoenix_controller: controller, phoenix_action: action}}) do
    [
      {:format, format},
      {:controller, controller |> inspect},
      {:action, action |> Atom.to_string}
    ]
  end
  defp formatted_phoenix_info(_), do: []

  defp get_params(%{params: params}) do
    params
    |> do_filter_params(Application.get_env(:logster, :filter_parameters, @default_filter_parameters))
    |> do_format_values
  end

  def do_filter_params(%{__struct__: mod} = struct, _params_to_filter) when is_atom(mod), do: struct
  def do_filter_params(%{} = map, params_to_filter) do
    Enum.into map, %{}, fn {k, v} ->
      if is_binary(k) && String.contains?(k, params_to_filter) do
        {k, "[FILTERED]"}
      else
        {k, do_filter_params(v, params_to_filter)}
      end
    end
  end
  def do_filter_params([_|_] = list, params_to_filter), do: Enum.map(list, &do_filter_params(&1, params_to_filter))
  def do_filter_params(other, _params_to_filter), do: other

  def do_format_values(%{} = params), do: params |> Enum.map(&do_format_value/1) |> Enum.into(%{})

  def do_format_value({key, value}) when is_binary(value) do
    if String.valid?(value) do
      {key, value}
    else
      {key, URI.encode(value)}
    end
  end
  def do_format_value(val), do: val

  defp log_level(%{private: %{logster_log_level: logster_log_level}}, _opts), do: logster_log_level
  defp log_level(_, opts), do: Keyword.get(opts, :log, :info)
end
