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
    * `:formatter` - The formatter module to use, has to implement `format/1`.
      Default is `Logster.StringFormatter`.
    * `:renames` - Map of fields to rename, for example: `%{status: :mystatus}`.
    * `:excludes` - List of fields to exclude from the log, for example: `[:params]`.
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
    formatter = Keyword.get(opts, :formatter, Logster.StringFormatter)

    if Application.get_env(:logster, :log_on_call, false) do
      Logger.log(log_level(conn, opts), fn ->
        construct_entry(conn, opts)
        |> formatter.format_on_call
      end)
    end

    Conn.register_before_send(conn, fn conn ->
      Logger.log(log_level(conn, opts), fn ->
        stop_time = current_time()
        duration = time_diff(start_time, stop_time)
        renames = Keyword.get(opts, :renames, %{})

        construct_entry(conn, opts)
        |> Keyword.merge(response_body(conn))
        |> put_field(:duration, renames, formatted_duration(duration))
        |> formatter.format
      end)

      conn
    end)
  end

  defp construct_entry(conn, opts) do
    renames = Keyword.get(opts, :renames, %{})

    []
    |> put_field(:method, renames, conn.method)
    |> put_field(:path, renames, conn.request_path)
    |> Keyword.merge(formatted_phoenix_info(conn))
    |> put_field(:params, renames, get_params(conn))
    |> put_field(:status, renames, conn.status)
    |> put_field(:state, renames, conn.state)
    |> Keyword.merge(
      headers(
        conn.req_headers,
        Application.get_env(:logster, :allowed_headers, @default_allowed_headers)
      )
    )
    |> Keyword.merge(Logger.metadata())
    |> exclude(Keyword.get(opts, :excludes, []))
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
    resp = Jason.decode!(body)
    |> do_filter_params(Application.get_env(:logster, :filter_parameters, @default_filter_parameters))
    |> do_format_values
    [{:resp_body, resp}]
  rescue
    _ ->
      [{:resp_body, "[Could not parse]"}]
  end

  defp put_field(keyword, default_key, renames, value) do
    Keyword.put(keyword, Map.get(renames, default_key, default_key), value)
  end

  defp headers(_, []), do: []

  defp headers(conn_headers, allowed_headers) do
    map =
      conn_headers
      |> Enum.filter(fn {k, _} -> Enum.member?(allowed_headers, k) end)
      |> Enum.into(%{}, fn {k, v} -> {k, v} end)

    [{:headers, map}]
  end

  defp exclude(keyword, excludes) do
    Keyword.drop(keyword, excludes)
  end

  defp current_time, do: :erlang.monotonic_time()

  defp time_diff(start, stop),
    do: (stop - start) |> :erlang.convert_time_unit(:native, :micro_seconds)

  defp formatted_duration(duration), do: duration / 1000

  defp formatted_phoenix_info(%{
         private: %{
           phoenix_format: format,
           phoenix_controller: controller,
           phoenix_action: action
         }
       }) do
    [
      {:format, format},
      {:controller, controller |> inspect},
      {:action, action |> Atom.to_string()}
    ]
  end

  defp formatted_phoenix_info(_), do: []

  defp get_params(%{params: _params = %Plug.Conn.Unfetched{}}), do: %{}

  defp get_params(%{params: params}) do
    params
    |> do_limit_params(Application.get_env(:logster, :parameter_limit, :infinity))
    |> do_filter_params(Application.get_env(:logster, :filter_parameters, @default_filter_parameters))
    |> do_format_values
  end

  defp do_limit_params(val, :infinity), do: val
  defp do_limit_params(val, allowed_size) do
    case do_calc_param_size(val, allowed_size) do
      size when is_integer(size) -> val
      :exceeds -> %{"truncated" => true}
    end
  end

  @typep size :: integer | :exceeds

  @spec do_calc_param_size(any, non_neg_integer) :: size
  defp do_calc_param_size(%{__struct__: _}, _maximum_size), do: 1
  defp do_calc_param_size(%{} = map, maximum_size) do
    Enum.reduce_while(map, 2, fn
      {k, v}, current_size ->
        new_size = add_sizes(do_calc_param_size(k, maximum_size - current_size),
                             do_calc_param_size(v, maximum_size - current_size))
        case new_size do
          :exceeds -> {:halt, :exceeds}
          size ->
            size = size + current_size + 1
            if size > maximum_size do {:halt, :exceeds} else {:cont, size} end
        end
    end)
  end
  defp do_calc_param_size(b, maximum_size) when is_binary(b) do
    Kernel.byte_size(b)
    |> maybe_exceeds(maximum_size)
  end
  defp do_calc_param_size(b, _maximum_size) when is_boolean(b), do: 5
  defp do_calc_param_size(number, _maximum_size) when is_number(number), do: to_string(number) |> Kernel.byte_size
  defp do_calc_param_size(list, maximum_size) when is_list(list) do
    Enum.reduce_while(list, 2, fn
      e, current_size ->
        new_size = do_calc_param_size(e, maximum_size - current_size)
        case new_size do
          :exceeds -> {:halt, :exceeds}
          size ->
            size = size + current_size + 1
            if size > maximum_size do {:halt, :exceeds} else {:cont, size} end
        end
    end)
  end
  defp do_calc_param_size(_, _maximum_size), do: 1

  @spec add_sizes(size, size) :: size
  defp add_sizes(:exceeds, _), do: :exceeds
  defp add_sizes(_, :exceeds), do: :exceeds
  defp add_sizes(a, b), do: a + b

  defp maybe_exceeds(size, maximum_size) do
    if size > maximum_size do
      :exceeds
    else
      size
    end
  end

  def do_filter_params(%{__struct__: mod} = struct, params_to_filter) when is_atom(mod),
    do: do_filter_params(Map.from_struct(struct), params_to_filter)

  def do_filter_params(%{} = map, params_to_filter) do
    Enum.into(map, %{}, fn {k, v} ->
      if is_binary(k) && String.contains?(k, params_to_filter) do
        {k, "[FILTERED]"}
      else
        {k, do_filter_params(v, params_to_filter)}
      end
    end)
  end

  def do_filter_params([_ | _] = list, params_to_filter),
    do: Enum.map(list, &do_filter_params(&1, params_to_filter))

  def do_filter_params(other, _params_to_filter), do: other

  def do_format_values([]), do: []
  def do_format_values(params) when is_list(params), do: params |> Enum.into([], &do_format_value/1)
  def do_format_values(%_{} = params), do: params |> Map.from_struct() |> do_format_values()

  def do_format_values(%{} = params), do: params |> Enum.into(%{}, &do_format_value/1)

  def do_format_value({key, value}) when is_binary(value) do
    if String.valid?(value) do
      {key, value}
    else
      {key, URI.encode(value)}
    end
  end

  def do_format_value(val), do: val

  defp log_level(%{private: %{logster_log_level: logster_log_level}}, _opts),
    do: logster_log_level

  defp log_level(_, opts), do: Keyword.get(opts, :log, :info)
end
