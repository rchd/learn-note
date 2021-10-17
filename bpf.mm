<map version="0.9.0">

<node COLOR="#000000">
<font NAME="SansSerif" SIZE="20"/>
<richcontent TYPE="NODE">
<html>
<head>
</head>
<body>
<p>
</p>
</body>
</html>
</richcontent>
<node COLOR="#0033ff" ID="sec-1" POSITION="right" FOLDED="true">
<font NAME="SansSerif" SIZE="18"/>
<edge STYLE="sharp_bezier" WIDTH="8"/>

<richcontent TYPE="NODE">
<html>
<head>
</head>
<body>
<p>bpf
</p>
</body>
</html>
</richcontent>
</node>


<node COLOR="#0033ff" ID="sec-2" POSITION="left" FOLDED="true">
<font NAME="SansSerif" SIZE="18"/>
<edge STYLE="sharp_bezier" WIDTH="8"/>

<richcontent TYPE="NODE">
<html>
<head>
</head>
<body>
<p>安装bcc
</p>
</body>
</html>
</richcontent>
<richcontent TYPE="NOTE">
<html>
<head>
</head>
<body>
<p>
在Gentoo中安装，在Gentoo中bcc是被屏蔽掉的
</p>
<div class="org-src-container">
<pre class="src src-sh">emerge --ask sys-kernel/gentoo-source
<span style="font-weight: bold;">echo</span> <span style="color: #8a3b3c;">"dev-util/bcc"</span> &gt;&gt; /etc/portage/package.unmask 
<span style="font-weight: bold;">echo</span> <span style="color: #8a3b3c;">"dev-util/bcc ~amd64"</span> &gt;&gt; /etc/portage/package.keywords
emerge --ask dev-util/bcc
</pre>
</div>

<p>
在ubuntu中安装，执行下列命令
</p>
<div class="org-src-container">
<pre class="src src-sh">apt install bcc-tools 
apt install python3-bpfcc
</pre>
</div>
</body>
</html>
</richcontent>
</node>


<node COLOR="#0033ff" ID="sec-3" POSITION="right" FOLDED="true">
<font NAME="SansSerif" SIZE="18"/>
<edge STYLE="sharp_bezier" WIDTH="8"/>

<richcontent TYPE="NODE">
<html>
<head>
</head>
<body>
<p>BPF程序的种类
</p>
</body>
</html>
</richcontent>
<node COLOR="#00b439" ID="sec-3-1" POSITION="right" FOLDED="false">
<font NAME="SansSerif" SIZE="16"/>
<edge STYLE="bezier" WIDTH="thin"/>

<richcontent TYPE="NODE">
<html>
<head>
</head>
<body>
<p>Socket Filter Programs
</p>
</body>
</html>
</richcontent>
<richcontent TYPE="NOTE">
<html>
<head>
</head>
<body>
<p>
BPF<sub>PROG</sub><sub>TYPE</sub><sub>SOCKET</sub><sub>FILTER是第一个初添加到Linux内核的bpf程序</sub>，当使用这类bpf程序
能够获得在处理socket中所有数据包。Socket filter program不允许用户修改数据包的内容
或数据包的目标地址，仅仅只能作观测使用。你的程序从相关的网络栈中接收数据，比如协议
类型，是被用来传递数据的。
</p>
</body>
</html>
</richcontent>
</node>

<node COLOR="#00b439" ID="sec-3-2" POSITION="right" FOLDED="false">
<font NAME="SansSerif" SIZE="16"/>
<edge STYLE="bezier" WIDTH="thin"/>

<richcontent TYPE="NODE">
<html>
<head>
</head>
<body>
<p>Kprobe Programs
</p>
</body>
</html>
</richcontent>
<richcontent TYPE="NOTE">
<html>
<head>
</head>
<body>
<p>
kprobes是使得在内核中动态附加到某一个调用点的函数，BPF kprobe类型的程序允许你使用
BPF支程序作为kprobe例程。BPF虚拟机确保你的kprobe程序总是安全运行，对于传统的kprobe
模块是一个优点。
</p>

<p>
当你写一个BPF程序被附加到kprobe中时，需要决定是
</p>
</body>
</html>
</richcontent>
</node>

<node COLOR="#00b439" ID="sec-3-3" POSITION="right" FOLDED="false">
<font NAME="SansSerif" SIZE="16"/>
<edge STYLE="bezier" WIDTH="thin"/>

<richcontent TYPE="NODE">
<html>
<head>
</head>
<body>
<p>Tracepoint Programs
</p>
</body>
</html>
</richcontent>
</node>


<node COLOR="#00b439" ID="sec-3-4" POSITION="right" FOLDED="false">
<font NAME="SansSerif" SIZE="16"/>
<edge STYLE="bezier" WIDTH="thin"/>

<richcontent TYPE="NODE">
<html>
<head>
</head>
<body>
<p>XDP Programs
</p>
</body>
</html>
</richcontent>
</node>


<node COLOR="#00b439" ID="sec-3-5" POSITION="right" FOLDED="false">
<font NAME="SansSerif" SIZE="16"/>
<edge STYLE="bezier" WIDTH="thin"/>

<richcontent TYPE="NODE">
<html>
<head>
</head>
<body>
<p>Perf Event Program
</p>
</body>
</html>
</richcontent>
</node>


<node COLOR="#00b439" ID="sec-3-6" POSITION="right" FOLDED="false">
<font NAME="SansSerif" SIZE="16"/>
<edge STYLE="bezier" WIDTH="thin"/>

<richcontent TYPE="NODE">
<html>
<head>
</head>
<body>
<p>Cgroup Open Socket Programs
</p>
</body>
</html>
</richcontent>
</node>


<node COLOR="#00b439" ID="sec-3-7" POSITION="right" FOLDED="false">
<font NAME="SansSerif" SIZE="16"/>
<edge STYLE="bezier" WIDTH="thin"/>

<richcontent TYPE="NODE">
<html>
<head>
</head>
<body>
<p>Socket Option Programs
</p>
</body>
</html>
</richcontent>
</node>


<node COLOR="#00b439" ID="sec-3-8" POSITION="right" FOLDED="false">
<font NAME="SansSerif" SIZE="16"/>
<edge STYLE="bezier" WIDTH="thin"/>

<richcontent TYPE="NODE">
<html>
<head>
</head>
<body>
<p>Socket Map Programs
</p>
</body>
</html>
</richcontent>
</node>


<node COLOR="#00b439" ID="sec-3-9" POSITION="right" FOLDED="false">
<font NAME="SansSerif" SIZE="16"/>
<edge STYLE="bezier" WIDTH="thin"/>

<richcontent TYPE="NODE">
<html>
<head>
</head>
<body>
<p>Cgroup Device Programs
</p>
</body>
</html>
</richcontent>
</node>


<node COLOR="#00b439" ID="sec-3-10" POSITION="right" FOLDED="false">
<font NAME="SansSerif" SIZE="16"/>
<edge STYLE="bezier" WIDTH="thin"/>

<richcontent TYPE="NODE">
<html>
<head>
</head>
<body>
<p>Socket Message Delivery Programs
</p>
</body>
</html>
</richcontent>
</node>


<node COLOR="#00b439" ID="sec-3-11" POSITION="right" FOLDED="false">
<font NAME="SansSerif" SIZE="16"/>
<edge STYLE="bezier" WIDTH="thin"/>

<richcontent TYPE="NODE">
<html>
<head>
</head>
<body>
<p>Raw Tracepoint Programs
</p>
</body>
</html>
</richcontent>
</node>


<node COLOR="#00b439" ID="sec-3-12" POSITION="right" FOLDED="false">
<font NAME="SansSerif" SIZE="16"/>
<edge STYLE="bezier" WIDTH="thin"/>

<richcontent TYPE="NODE">
<html>
<head>
</head>
<body>
<p>Cgroup Socket Address Programs
</p>
</body>
</html>
</richcontent>
</node>


<node COLOR="#00b439" ID="sec-3-13" POSITION="right" FOLDED="false">
<font NAME="SansSerif" SIZE="16"/>
<edge STYLE="bezier" WIDTH="thin"/>

<richcontent TYPE="NODE">
<html>
<head>
</head>
<body>
<p>Socket Reuseport Programs
</p>
</body>
</html>
</richcontent>
</node>


<node COLOR="#00b439" ID="sec-3-14" POSITION="right" FOLDED="false">
<font NAME="SansSerif" SIZE="16"/>
<edge STYLE="bezier" WIDTH="thin"/>

<richcontent TYPE="NODE">
<html>
<head>
</head>
<body>
<p>Flow Dissection Programs
</p>
</body>
</html>
</richcontent>
</node>

</node>


<node COLOR="#0033ff" ID="sec-4" POSITION="left" FOLDED="true">
<font NAME="SansSerif" SIZE="18"/>
<edge STYLE="sharp_bezier" WIDTH="8"/>

<richcontent TYPE="NODE">
<html>
<head>
</head>
<body>
<p>BPF虚拟文件系统
</p>
</body>
</html>
</richcontent>
<richcontent TYPE="NOTE">
<html>
<head>
</head>
<body>
<div class="org-src-container">
<pre class="src src-c"><span style="font-weight: bold;">static</span> <span style="font-weight: bold;">const</span> <span style="font-weight: bold;">char</span> * <span style="color: #383a42;">file_path</span>=<span style="color: #8a3b3c;">"/sys/fs/bpf/my_array"</span>;
<span style="font-weight: bold;">int</span> <span style="font-weight: bold;">main</span>(<span style="font-weight: bold;">int</span> <span style="color: #383a42;">argc</span>, <span style="font-weight: bold;">char</span> **<span style="color: #383a42;">argv</span>)
{
  <span style="font-weight: bold;">int</span> <span style="color: #383a42;">key</span>, <span style="color: #383a42;">value</span>, <span style="color: #383a42;">fd</span>, <span style="color: #383a42;">added</span>, <span style="color: #383a42;">pinned</span>;
  fd=bpf_create_map(BPF_MAP_TYPE_ARRAY,<span style="font-weight: bold;">sizeof</span>(<span style="font-weight: bold;">int</span>),<span style="font-weight: bold;">sizeof</span>(<span style="font-weight: bold;">int</span>),100,0);
  <span style="font-weight: bold;">if</span>(fd&lt;0){
    printf(<span style="color: #8a3b3c;">"Failed to create map: %d (%s)\n"</span>, fd, strerror(errno));
    <span style="font-weight: bold;">return</span> -1;
  }
  key=1,value=1234;
  added=bpf_map_update_elem(fd, &amp;key, &amp;value, BPF_ANY);
  <span style="font-weight: bold;">if</span>(added&lt;0){
    printf(<span style="color: #8a3b3c;">"Failed to update map: %d (%s)\n"</span>, added, strerror(errno));
    <span style="font-weight: bold;">return</span> -1;
  }
  pinned=bpf_obj_pin(fd, file_path);
  <span style="font-weight: bold;">if</span>(pineed&lt;0){
    printf(<span style="color: #8a3b3c;">"Failed to pin map to the file system: %d (%s)\n"</span>,
           pinned,strerror(errno));
    <span style="font-weight: bold;">return</span> -1;
  }
  <span style="font-weight: bold;">return</span> 0;
}
</pre>
</div>

<div class="org-src-container">
<pre class="src src-c"><span style="font-weight: bold;">static</span> <span style="font-weight: bold;">const</span> <span style="font-weight: bold;">char</span> * <span style="color: #383a42;">file_path</span>=<span style="color: #8a3b3c;">"/sys/fs/bpf/my_array"</span>;

<span style="font-weight: bold;">int</span> <span style="font-weight: bold;">main</span>(<span style="font-weight: bold;">int</span> <span style="color: #383a42;">argc</span>, <span style="font-weight: bold;">char</span> **<span style="color: #383a42;">argv</span>){
  <span style="font-weight: bold;">int</span> <span style="color: #383a42;">fd</span>, <span style="color: #383a42;">key</span>, <span style="color: #383a42;">value</span>, <span style="color: #383a42;">result</span>;

  fd=bpf_obj_get(file_path);
  <span style="font-weight: bold;">if</span>(fd&lt;0){
    printf(<span style="color: #8a3b3c;">"Failed to fetch the map: %d (%s)\n"</span>, fd, strerror(errno));
    <span style="font-weight: bold;">return</span> -1;
  }

  key=1;
  result=bpf_map_lookup_elem(fd, &amp;key, &amp;value);
  <span style="font-weight: bold;">if</span>(result&lt;0){
    printf(<span style="color: #8a3b3c;">"Failed to read value from the map: %d (%s)\n"</span>,
           result, strerror(errno));
    <span style="font-weight: bold;">return</span> -1;
  }

  printf(<span style="color: #8a3b3c;">"Value read from the map: '%d'\n"</span>, value);
  <span style="font-weight: bold;">return</span> 0;
}
</pre>
</div>
</body>
</html>
</richcontent>
<node COLOR="#00b439" ID="sec-4-1" POSITION="left" FOLDED="false">
<font NAME="SansSerif" SIZE="16"/>
<edge STYLE="bezier" WIDTH="thin"/>

<richcontent TYPE="NODE">
<html>
<head>
</head>
<body>
<p>Kprobes示例
</p>
</body>
</html>
</richcontent>
<richcontent TYPE="NOTE">
<html>
<head>
</head>
<body>
<div class="org-src-container">
<pre class="src src-python"><span style="font-weight: bold;">from</span> bcc <span style="font-weight: bold;">import</span> BPF
<span style="color: #383a42;">bpf_source</span>=<span style="color: #8a3b3c;">"""</span>
<span style="color: #8a3b3c;">int do_sys_execve(struct pt_regs *ctx, void filename, void argv, void envp){</span>
<span style="color: #8a3b3c;">    char comm[16];</span>
<span style="color: #8a3b3c;">    bpf_get_current_comm(&amp;comm, sizeof(comm));</span>
<span style="color: #8a3b3c;">    bpf_trace_printk("executing program: %s", comm);</span>
<span style="color: #8a3b3c;">    return 0;</span>
<span style="color: #8a3b3c;">}</span>
<span style="color: #8a3b3c;">"""</span>
<span style="color: #383a42;">bpf</span>=BPF(text=bpf_source)
<span style="color: #383a42;">execve_function</span>=bpf.get_syscall_fnname(<span style="color: #8a3b3c;">"execve"</span>)
bpf.attach_kprobe(event=execve_function, fn_name=<span style="color: #8a3b3c;">"do_sys_execve"</span>)
bpf.trace_print()
</pre>
</div>
<p>
bpf程序开始时，bpf<sub>get</sub><sub>current</sub><sub>comm会先获取当前内核的命令名</sub>，把它赋给comm变量。
定义的定长数组，因为内核对命令名有16个字符的限制，获取命令之后，把它输出到调试
跟踪，所以用户通过Python脚本，使用BPF获取所有命令
加载BPF程序到内核
关联程序到execve系统调用，不同内核版本的系统调用不同，BCC提供的相关函数使得不
需要记住运行的系统版本
该代码输出到跟踪日志，所有可以看到所有的跟踪信息
</p>
</body>
</html>
</richcontent>
</node>


<node COLOR="#00b439" ID="sec-4-2" POSITION="left" FOLDED="false">
<font NAME="SansSerif" SIZE="16"/>
<edge STYLE="bezier" WIDTH="thin"/>

<richcontent TYPE="NODE">
<html>
<head>
</head>
<body>
<p>Kretprobes示例
</p>
</body>
</html>
</richcontent>
<richcontent TYPE="NOTE">
<html>
<head>
</head>
<body>
<div class="org-src-container">
<pre class="src src-python"><span style="font-weight: bold;">from</span> bcc <span style="font-weight: bold;">import</span> BPF

<span style="color: #383a42;">bpf_source</span>= <span style="color: #8a3b3c;">"""</span>
<span style="color: #8a3b3c;">int ret_sys_execve(struct pt_regs *ctx){</span>
<span style="color: #8a3b3c;">int return_value;</span>
<span style="color: #8a3b3c;">char comm[16];</span>
<span style="color: #8a3b3c;">bpf_get_current_comm(&amp;comm, sizeof(comm));</span>
<span style="color: #8a3b3c;">return_value=PI_REGS_RC(ctx);</span>

<span style="color: #8a3b3c;">bpf_trace_printk("program: %s, return: %d", comm, return_value);</span>

<span style="color: #8a3b3c;">return 0;</span>
<span style="color: #8a3b3c;">}</span>
<span style="color: #8a3b3c;">"""</span>

<span style="color: #383a42;">bpf</span>=BPF(text=bpf_source)
<span style="color: #383a42;">execve_function</span>=bpf.get_syscall_fnname(<span style="color: #8a3b3c;">"execve"</span>)
bpf.attach_kretprobe(event=execve_function, fn_name=<span style="color: #8a3b3c;">"ret_sys_execve"</span>)
bpf.trace_print()
</pre>
</div>
<p>
定义一个函数实现BPF程序，内核会在execve系统调用之后立刻执行该程序，PT<sub>REGS</sub><sub>RC是一个</sub>
宏，读取从BPF寄存器在特定的上下文的值，也会使用bpf<sub>trace</sub><sub>printk输出命令</sub>，将值输出到
调度日志。
初始化BPF程序接着加载到内核
修改附加函数到attach<sub>kretprobe</sub>
</p>
</body>
</html>
</richcontent>
</node>


<node COLOR="#00b439" ID="sec-4-3" POSITION="left" FOLDED="false">
<font NAME="SansSerif" SIZE="16"/>
<edge STYLE="bezier" WIDTH="thin"/>

<richcontent TYPE="NODE">
<html>
<head>
</head>
<body>
<p>Tracepoints示例
</p>
</body>
</html>
</richcontent>
<richcontent TYPE="NOTE">
<html>
<head>
</head>
<body>
<div class="org-src-container">
<pre class="src src-python"><span style="font-weight: bold;">from</span> bcc <span style="font-weight: bold;">import</span> BPF

<span style="color: #383a42;">bpf_source</span>= <span style="color: #8a3b3c;">"""</span>
<span style="color: #8a3b3c;">int trace_bpf_prog_load(void ctx){</span>
<span style="color: #8a3b3c;">char comm[16];</span>
<span style="color: #8a3b3c;">bpf_get_current_comm(&amp;comm, sizeof(comm));</span>

<span style="color: #8a3b3c;">bpf_trace_printk("%s is loading a BPF program", comm);</span>
<span style="color: #8a3b3c;">return 0;</span>
<span style="color: #8a3b3c;">}</span>
<span style="color: #8a3b3c;">"""</span>

<span style="color: #383a42;">bpf</span>=BPF(text=bpf_source)
bpf.attach_tracepoint(tp=<span style="color: #8a3b3c;">"bpf:bpf_prog_load"</span>,
                      fn_name=<span style="color: #8a3b3c;">"trace_prog_load"</span>)
bpf.trace_print()
</pre>
</div>

<p>
声明一个函数定义BPF程序，代码有kprobes有些不同
</p>
</body>
</html>
</richcontent>
</node>

</node>


<node COLOR="#0033ff" ID="sec-5" POSITION="right" FOLDED="true">
<font NAME="SansSerif" SIZE="18"/>
<edge STYLE="sharp_bezier" WIDTH="8"/>

<richcontent TYPE="NODE">
<html>
<head>
</head>
<body>
<p>User-Space Probes
</p>
</body>
</html>
</richcontent>
<node COLOR="#00b439" ID="sec-5-1" POSITION="right" FOLDED="false">
<font NAME="SansSerif" SIZE="16"/>
<edge STYLE="bezier" WIDTH="thin"/>

<richcontent TYPE="NODE">
<html>
<head>
</head>
<body>
<p>Uprobes
</p>
</body>
</html>
</richcontent>
<richcontent TYPE="NOTE">
<html>
<head>
</head>
<body>
<div class="org-src-container">
<pre class="src src-go">package main
import "fmt"
func main(){
   fmt.Println("Hello, BPF")
}
</pre>
</div>

<div class="org-src-container">
<pre class="src src-python"><span style="font-weight: bold;">from</span> bcc <span style="font-weight: bold;">import</span> BPF

<span style="color: #383a42;">bpf_source</span>=<span style="color: #8a3b3c;">"""</span>
<span style="color: #8a3b3c;">int trace_go_main(strcut pt_regs *ctx){</span>
<span style="color: #8a3b3c;">u64 pid=bpf_get_current_tgid();</span>
<span style="color: #8a3b3c;">bpf_trace_printk("New hello-bpf process running with PID: %d", pid);</span>
<span style="color: #8a3b3c;">}</span>
<span style="color: #8a3b3c;">"""</span>

<span style="color: #383a42;">bpf</span>=BPF(text=bpf_source)
bpf.attach_uprobe(name=<span style="color: #8a3b3c;">"hello-bpf"</span>,
                  sym=<span style="color: #8a3b3c;">"main.main"</span>, fn_name=<span style="color: #8a3b3c;">"trace_go_main"</span>)
bpf.trace_print()
</pre>
</div>
</body>
</html>
</richcontent>
</node>

</node>

</node>
</map>
