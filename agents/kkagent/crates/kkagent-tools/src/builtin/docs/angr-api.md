# angr API Reference

> 由 angr 官方 API 文档（api.angr.io）与官方教程/概念文档（docs.angr.io）转换汇编，2026-08 抓取。

> 章节顺序：Quickstart → 核心概念 → angr 模块 API → claripy。所有方法签名、参数与说明保持官方原文。

---

## Angr Quickstart（官方 docs.angr.io）

angr is a multi-architecture binary analysis toolkit, with the capability to perform dynamic symbolic execution (like Mayhem, KLEE, etc.) and various static analyses on binaries. If you’d like to learn how to use it, you’re in the right place!

We’ve tried to make using angr as pain-free as possible - our goal is to create a user-friendly binary analysis suite, allowing a user to simply start up iPython and easily perform intensive binary analyses with a couple of commands. That being said, binary analysis is complex, which makes angr complex. This documentation is an attempt to help out with that, providing narrative explanation and exploration of angr and its design.

Several challenges must be overcome to programmatically analyze a binary. They are, roughly:

- Loading a binary into the analysis program.

- Translating a binary into an intermediate representation (IR).

- Performing the actual analysis. This could be:

  - A partial or full-program static analysis (i.e., dependency analysis, program slicing).

  - A symbolic exploration of the program’s state space (i.e., “Can we execute it until we find an overflow?”).

  - Some combination of the above (i.e., “Let’s execute only program slices that lead to a memory write, to find an overflow.”)

angr has components that meet all of these challenges. This documentation will explain how each component works, and how they can all be used to accomplish your goals.

## Getting Support

To get help with angr, you can:

- Chat with us on the angr Discord server

- Open an issue on the appropriate GitHub repository

## Citing angr

If you use angr in an academic work, please cite the papers for which it was developed:

```
@article{shoshitaishvili2016state,
  title={SoK: (State of) The Art of War: Offensive Techniques in Binary Analysis},
  author={Shoshitaishvili, Yan and Wang, Ruoyu and Salls, Christopher and Stephens, Nick and Polino, Mario and Dutcher, Audrey and Grosen, Jessie and Feng, Siji and Hauser, Christophe and Kruegel, Christopher and Vigna, Giovanni},
  booktitle={IEEE Symposium on Security and Privacy},
  year={2016}
}

@article{stephens2016driller,
  title={Driller: Augmenting Fuzzing Through Selective Symbolic Execution},
  author={Stephens, Nick and Grosen, Jessie and Salls, Christopher and Dutcher, Audrey and Wang, Ruoyu and Corbetta, Jacopo and Shoshitaishvili, Yan and Kruegel, Christopher and Vigna, Giovanni},
  booktitle={NDSS},
  year={2016}
}

@article{shoshitaishvili2015firmalice,
  title={Firmalice - Automatic Detection of Authentication Bypass Vulnerabilities in Binary Firmware},
  author={Shoshitaishvili, Yan and Wang, Ruoyu and Hauser, Christophe and Kruegel, Christopher and Vigna, Giovanni},
  booktitle={NDSS},
  year={2015}
}

```

## Going further

You can read this paper, explaining some of the internals, algorithms, and used techniques to get a better understanding on what’s going on under the hood.

If you enjoy playing CTFs and would like to learn angr in a similar fashion, angr_ctf will be a fun way for you to get familiar with much of the symbolic execution capability of angr. The angr_ctf repo is maintained by @jakespringer.

---

## 核心概念：总览（Top Level）

To get started with angr, you’ll need to have a basic overview of some fundamental angr concepts and how to construct some basic angr objects. We’ll go over this by examining what’s directly available to you after you’ve loaded a binary!

Your first action with angr will always be to load a binary into a *project*. We’ll use `/bin/true` for these examples.

```
>>> import angr
>>> proj = angr.Project('/bin/true')

```

A project is your control base in angr. With it, you will be able to dispatch analyses and simulations on the executable you just loaded. Almost every single object you work with in angr will depend on the existence of a project in some form.

> > **Tip**

Using and exploring angr in IPython (or other Python command line interpreters) is a main use case that we design angr for. When you are not sure what interfaces are available, tab completion is your friend!

Sometimes tab completion in IPython can be slow. We find the following workaround helpful without degrading the validity of completion results:

```
# Drop this file in IPython profile's startup directory to avoid running it every time.
import IPython
py = IPython.get_ipython()
py.Completer.use_jedi = False

```

## Basic properties

First, we have some basic properties about the project: its CPU architecture, its filename, and the address of its entry point.

```
>>> import monkeyhex # this will format numerical results in hexadecimal
>>> proj.arch
<Arch AMD64 (LE)>
>>> proj.entry
0x401670
>>> proj.filename
'/bin/true'

```

- *arch* is an instance of an `archinfo.Arch` object for whichever architecture the program is compiled, in this case little-endian amd64. It contains a ton of clerical data about the CPU it runs on, which you can peruse at your leisure. The common ones you care about are `arch.bits`, `arch.bytes` (that one is a `@property` declaration on the main Arch class), `arch.name`, and `arch.memory_endness`.

- *entry* is the entry point of the binary!

- *filename* is the absolute filename of the binary. Riveting stuff!

## Loading

Getting from a binary file to its representation in a virtual address space is pretty complicated! We have a module called CLE to handle that. CLE’s result, called the loader, is available in the `.loader` property. We’ll get into detail on how to use this soon, but for now just know that you can use it to see the shared libraries that angr loaded alongside your program and perform basic queries about the loaded address space.

```
>>> proj.loader
<Loaded true, maps [0x400000:0x5004000]>

>>> proj.loader.shared_objects # may look a little different for you!
{'ld-linux-x86-64.so.2': <ELF Object ld-2.24.so, maps [0x2000000:0x2227167]>,
 'libc.so.6': <ELF Object libc-2.24.so, maps [0x1000000:0x13c699f]>}

>>> proj.loader.min_addr
0x400000
>>> proj.loader.max_addr
0x5004000

>>> proj.loader.main_object  # we've loaded several binaries into this project. Here's the main one!
<ELF Object true, maps [0x400000:0x60721f]>

>>> proj.loader.main_object.execstack  # sample query: does this binary have an executable stack?
False
>>> proj.loader.main_object.pic  # sample query: is this binary position-independent?
True

```

## The factory

There are a lot of classes in angr, and most of them require a project to be instantiated. Instead of making you pass around the project everywhere, we provide `project.factory`, which has several convenient constructors for common objects you’ll want to use frequently.

This section will also serve as an introduction to several basic angr concepts. Strap in!

### Blocks

First, we have `project.factory.block()`, which is used to extract a basic block of code from a given address. This is an important fact - *angr analyzes code in units of basic blocks.* You will get back a Block object, which can tell you lots of fun things about the block of code:

```
>>> block = proj.factory.block(proj.entry) # lift a block of code from the program's entry point
<Block for 0x401670, 42 bytes>

>>> block.pp()                          # pretty-print a disassembly to stdout
0x401670:       xor     ebp, ebp
0x401672:       mov     r9, rdx
0x401675:       pop     rsi
0x401676:       mov     rdx, rsp
0x401679:       and     rsp, 0xfffffffffffffff0
0x40167d:       push    rax
0x40167e:       push    rsp
0x40167f:       lea     r8, [rip + 0x2e2a]
0x401686:       lea     rcx, [rip + 0x2db3]
0x40168d:       lea     rdi, [rip - 0xd4]
0x401694:       call    qword ptr [rip + 0x205866]

>>> block.instructions                  # how many instructions are there?
0xb
>>> block.instruction_addrs             # what are the addresses of the instructions?
[0x401670, 0x401672, 0x401675, 0x401676, 0x401679, 0x40167d, 0x40167e, 0x40167f, 0x401686, 0x40168d, 0x401694]

```

Additionally, you can use a Block object to get other representations of the block of code:

```
>>> block.capstone                       # capstone disassembly
<CapstoneBlock for 0x401670>
>>> block.vex                            # VEX IRSB (that's a Python internal address, not a program address)
<pyvex.block.IRSB at 0x7706330>

```

### States

Here’s another fact about angr - the `Project` object only represents an “initialization image” for the program. When you’re performing execution with angr, you are working with a specific object representing a *simulated program state* - a `SimState`. Let’s grab one right now!

```
>>> state = proj.factory.entry_state()
<SimState @ 0x401670>

```

A SimState contains a program’s memory, registers, filesystem data… any “live data” that can be changed by execution has a home in the state. We’ll cover how to interact with states in depth later, but for now, let’s use `state.regs` and `state.mem` to access the registers and memory of this state:

```
>>> state.regs.rip        # get the current instruction pointer
<BV64 0x401670>
>>> state.regs.rax
<BV64 0x1c>
>>> state.mem[proj.entry].int.resolved  # interpret the memory at the entry point as a C int
<BV32 0x8949ed31>

```

Those aren’t Python ints! Those are *bitvectors*. Python integers don’t have the same semantics as words on a CPU, e.g. wrapping on overflow, so we work with bitvectors, which you can think of as an integer as represented by a series of bits, to represent CPU data in angr. Note that each bitvector has a `.length` property describing how wide it is in bits.

We’ll learn all about how to work with them soon, but for now, here’s how to convert from Python ints to bitvectors and back again:

```
>>> bv = claripy.BVV(0x1234, 32)       # create a 32-bit-wide bitvector with value 0x1234
<BV32 0x1234>                               # BVV stands for bitvector value
>>> state.solver.eval(bv)                # convert to Python int
0x1234

```

You can store these bitvectors back to registers and memory, or you can directly store a Python integer and it’ll be converted to a bitvector of the appropriate size:

```
>>> state.regs.rsi = claripy.BVV(3, 64)
>>> state.regs.rsi
<BV64 0x3>

>>> state.mem[0x1000].long = 4
>>> state.mem[0x1000].long.resolved
<BV64 0x4>

```

The `mem` interface is a little confusing at first, since it’s using some pretty hefty Python magic. The short version of how to use it is:

- Use array[index] notation to specify an address

- Use `.<type>` to specify that the memory should be interpreted as `type` (common values: char, short, int, long, size_t, uint8_t, uint16_t…)

- From there, you can either:

  - Store a value to it, either a bitvector or a Python int

  - Use `.resolved` to get the value as a bitvector

  - Use `.concrete` to get the value as a Python int

There are more advanced usages that will be covered later!

Finally, if you try reading some more registers you may encounter a very strange looking value:

```
>>> state.regs.rdi
<BV64 reg_48_11_64{UNINITIALIZED}>

```

This is still a 64-bit bitvector, but it doesn’t contain a numerical value. Instead, it has a name! This is called a *symbolic variable* and it is the underpinning of symbolic execution. Don’t panic! We will discuss all of this in detail exactly two chapters from now.

### Simulation Managers

If a state lets us represent a program at a given point in time, there must be a way to get it to the *next* point in time. A simulation manager is the primary interface in angr for performing execution, simulation, whatever you want to call it, with states. As a brief introduction, let’s show how to tick that state we created earlier forward a few basic blocks.

First, we create the simulation manager we’re going to be using. The constructor can take a state or a list of states.

```
>>> simgr = proj.factory.simulation_manager(state)
<SimulationManager with 1 active>
>>> simgr.active
[<SimState @ 0x401670>]

```

A simulation manager can contain several *stashes* of states. The default stash, `active`, is initialized with the state we passed in. We could look at `simgr.active[0]` to look at our state some more, if we haven’t had enough!

Now… get ready, we’re going to do some execution.

```
>>> simgr.step()

```

We’ve just performed a basic block’s worth of symbolic execution! We can look at the active stash again, noticing that it’s been updated, and furthermore, that it has **not** modified our original state. SimState objects are treated as immutable by execution - you can safely use a single state as a “base” for multiple rounds of execution.

```
>>> simgr.active
[<SimState @ 0x1020300>]
>>> simgr.active[0].regs.rip                 # new and exciting!
<BV64 0x1020300>
>>> state.regs.rip                           # still the same!
<BV64 0x401670>

```

`/bin/true` isn’t a very good example for describing how to do interesting things with symbolic execution, so we’ll stop here for now.

## Analyses

angr comes pre-packaged with several built-in analyses that you can use to extract some fun kinds of information from a program. Here they are:

```
>>> proj.analyses.            # Press TAB here in ipython to get an autocomplete-listing of everything:
 proj.analyses.BackwardSlice        proj.analyses.CongruencyCheck      proj.analyses.reload_analyses
 proj.analyses.BinaryOptimizer      proj.analyses.DDG                  proj.analyses.StaticHooker
 proj.analyses.BinDiff              proj.analyses.DFG                  proj.analyses.VariableRecovery
 proj.analyses.BoyScout             proj.analyses.Disassembly          proj.analyses.VariableRecoveryFast
 proj.analyses.CDG                  proj.analyses.GirlScout            proj.analyses.Veritesting
 proj.analyses.CFG                  proj.analyses.Identifier           proj.analyses.VFG
 proj.analyses.CFGEmulated          proj.analyses.LoopFinder           proj.analyses.VSA_DDG
 proj.analyses.CFGFast              proj.analyses.Reassembler

```

A couple of these are documented later in this book, but in general, if you want to find how to use a given analysis, you should look in the api documentation for `angr.analyses`. As an extremely brief example: here’s how you construct and use a quick control-flow graph:

```
# Originally, when we loaded this binary it also loaded all its dependencies into the same virtual address  space
# This is undesirable for most analysis.
>>> proj = angr.Project('/bin/true', auto_load_libs=False)
>>> cfg = proj.analyses.CFGFast()
<CFGFast Analysis Result at 0x2d85130>

# cfg.graph is a networkx DiGraph full of CFGNode instances
# You should go look up the networkx APIs to learn how to use this!
>>> cfg.graph
<networkx.classes.digraph.DiGraph at 0x2da43a0>
>>> len(cfg.graph.nodes())
951

# To get the CFGNode for a given address, use cfg.model.get_any_node
>>> entry_node = cfg.model.get_any_node(proj.entry)
>>> len(list(cfg.graph.successors(entry_node)))
2

```

## Now what?

Having read this page, you should now be acquainted with several important angr concepts: basic blocks, states, bitvectors, simulation managers, and analyses. You can’t really do anything interesting besides just use angr as a glorified debugger, though! Keep reading, and you will unlock deeper powers…

---

## 核心概念：加载二进制（Loading a Binary）

Previously, you saw just the barest taste of angr’s loading facilities - you loaded `/bin/true`, and then loaded it again without its shared libraries. You also saw `proj.loader` and a few things it could do. Now, we’ll dive into the nuances of these interfaces and the things they can tell you.

We briefly mentioned angr’s binary loading component, CLE. CLE stands for “CLE Loads Everything”, and is responsible for taking a binary (and any libraries that it depends on) and presenting it to the rest of angr in a way that is easy to work with.

## The Loader

Let’s load `examples/fauxware/fauxware` and take a deeper look at how to interact with the loader.

```
>>> import angr, monkeyhex
>>> proj = angr.Project('examples/fauxware/fauxware')
>>> proj.loader
<Loaded fauxware, maps [0x400000:0x5008000]>

```

### Loaded Objects

The CLE loader (`cle.Loader`) represents an entire conglomerate of loaded *binary objects*, loaded and mapped into a single memory space. Each binary object is loaded by a loader backend that can handle its filetype (a subclass of `cle.Backend`). For example, `cle.ELF` is used to load ELF binaries.

There will also be objects in memory that don’t correspond to any loaded binary. For example, an object used to provide thread-local storage support, and an externs object used to provide unresolved symbols.

You can get the full list of objects that CLE has loaded with `loader.all_objects`, as well as several more targeted classifications:

```
# All loaded objects
>>> proj.loader.all_objects
[<ELF Object fauxware, maps [0x400000:0x60105f]>,
 <ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>,
 <ELF Object ld-2.23.so, maps [0x2000000:0x2227167]>,
 <ELFTLSObject Object cle##tls, maps [0x3000000:0x3015010]>,
 <ExternObject Object cle##externs, maps [0x4000000:0x4008000]>,
 <KernelObject Object cle##kernel, maps [0x5000000:0x5008000]>]

# This is the "main" object, the one that you directly specified when loading the project
>>> proj.loader.main_object
<ELF Object fauxware, maps [0x400000:0x60105f]>

# This is a dictionary mapping from shared object name to object
>>> proj.loader.shared_objects
{ 'fauxware': <ELF Object fauxware, maps [0x400000:0x60105f]>,
  'libc.so.6': <ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>,
  'ld-linux-x86-64.so.2': <ELF Object ld-2.23.so, maps [0x2000000:0x2227167]> }

# Here's all the objects that were loaded from ELF files
# If this were a windows program we'd use all_pe_objects!
>>> proj.loader.all_elf_objects
[<ELF Object fauxware, maps [0x400000:0x60105f]>,
 <ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>,
 <ELF Object ld-2.23.so, maps [0x2000000:0x2227167]>]

# Here's the "externs object", which we use to provide addresses for unresolved imports and angr internals
>>> proj.loader.extern_object
<ExternObject Object cle##externs, maps [0x4000000:0x4008000]>

# This object is used to provide addresses for emulated syscalls
>>> proj.loader.kernel_object
<KernelObject Object cle##kernel, maps [0x5000000:0x5008000]>

# Finally, you can to get a reference to an object given an address in it
>>> proj.loader.find_object_containing(0x400000)
<ELF Object fauxware, maps [0x400000:0x60105f]>

```

You can interact directly with these objects to extract metadata from them:

```
>>> obj = proj.loader.main_object

# The entry point of the object
>>> obj.entry
0x400580

>>> obj.min_addr, obj.max_addr
(0x400000, 0x60105f)

# Retrieve this ELF's segments and sections
>>> obj.segments
<Regions: [<ELFSegment memsize=0xa74, filesize=0xa74, vaddr=0x400000, flags=0x5, offset=0x0>,
           <ELFSegment memsize=0x238, filesize=0x228, vaddr=0x600e28, flags=0x6, offset=0xe28>]>
>>> obj.sections
<Regions: [<Unnamed | offset 0x0, vaddr 0x0, size 0x0>,
           <.interp | offset 0x238, vaddr 0x400238, size 0x1c>,
           <.note.ABI-tag | offset 0x254, vaddr 0x400254, size 0x20>,
            ...etc

# You can get an individual segment or section by an address it contains:
>>> obj.find_segment_containing(obj.entry)
<ELFSegment memsize=0xa74, filesize=0xa74, vaddr=0x400000, flags=0x5, offset=0x0>
>>> obj.find_section_containing(obj.entry)
<.text | offset 0x580, vaddr 0x400580, size 0x338>

# Get the address of the PLT stub for a symbol
>>> addr = obj.plt['strcmp']
>>> addr
0x400550
>>> obj.reverse_plt[addr]
'strcmp'

# Show the prelinked base of the object and the location it was actually mapped into memory by CLE
>>> obj.linked_base
0x400000
>>> obj.mapped_base
0x400000

```

### Symbols and Relocations

You can also work with symbols while using CLE. A symbol is a fundamental concept in the world of executable formats, effectively mapping a name to an address.

The easiest way to get a symbol from CLE is to use `loader.find_symbol`, which takes either a name or an address and returns a Symbol object.

```
>>> strcmp = proj.loader.find_symbol('strcmp')
>>> strcmp
<Symbol "strcmp" in libc.so.6 at 0x1089cd0>

```

The most useful attributes on a symbol are its name, its owner, and its address, but the “address” of a symbol can be ambiguous. The Symbol object has three ways of reporting its address:

- `.rebased_addr` is its address in the global address space. This is what is shown in the print output.

- `.linked_addr` is its address relative to the prelinked base of the binary. This is the address reported in, for example, `readelf(1)`.

- `.relative_addr` is its address relative to the object base. This is known in the literature (particularly the Windows literature) as an RVA (relative virtual address).

```
>>> strcmp.name
'strcmp'

>>> strcmp.owner
<ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>

>>> strcmp.rebased_addr
0x1089cd0
>>> strcmp.linked_addr
0x89cd0
>>> strcmp.relative_addr
0x89cd0

```

In addition to providing debug information, symbols also support the notion of dynamic linking. libc provides the strcmp symbol as an export, and the main binary depends on it. If we ask CLE to give us a strcmp symbol from the main object directly, it’ll tell us that this is an *import symbol*. Import symbols do not have meaningful addresses associated with them, but they do provide a reference to the symbol that was used to resolve them, as `.resolvedby`.

```
>>> strcmp.is_export
True
>>> strcmp.is_import
False

# On Loader, the method is find_symbol because it performs a search operation to find the symbol.
# On an individual object, the method is get_symbol because there can only be one symbol with a given name.
>>> main_strcmp = proj.loader.main_object.get_symbol('strcmp')
>>> main_strcmp
<Symbol "strcmp" in fauxware (import)>
>>> main_strcmp.is_export
False
>>> main_strcmp.is_import
True
>>> main_strcmp.resolvedby
<Symbol "strcmp" in libc.so.6 at 0x1089cd0>

```

The specific ways that the links between imports and exports should be registered in memory are handled by another notion called *relocations*. A relocation says, “when you match *[import]* up with an export symbol, please write the export’s address to *[location]*, formatted as *[format]*.” We can see the full list of relocations for an object (as `Relocation` instances) as `obj.relocs`, or just a mapping from symbol name to Relocation as `obj.imports`. There is no corresponding list of export symbols.

A relocation’s corresponding import symbol can be accessed as `.symbol`. The address the relocation will write to is accessible through any of the address identifiers you can use for Symbol, and you can get a reference to the object requesting the relocation with `.owner` as well.

```
# Relocations don't have a good pretty-printing, so those addresses are Python-internal, unrelated to our program
>>> proj.loader.shared_objects['libc.so.6'].imports
{'__libc_enable_secure': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fce780>,
 '__tls_get_addr': <cle.backends.elf.relocation.amd64.R_X86_64_JUMP_SLOT at 0x7ff5c6018358>,
 '_dl_argv': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fd2e48>,
 '_dl_find_dso_for_object': <cle.backends.elf.relocation.amd64.R_X86_64_JUMP_SLOT at 0x7ff5c6018588>,
 '_dl_starting_up': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fd2550>,
 '_rtld_global': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fce4e0>,
 '_rtld_global_ro': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fcea20>}

```

If an import cannot be resolved to any export, for example, because a shared library could not be found, CLE will automatically update the externs object (`loader.extern_obj`) to claim it provides the symbol as an export.

## Loading Options

If you are loading something with `angr.Project` and you want to pass an option to the `cle.Loader` instance that Project implicitly creates, you can just pass the keyword argument directly to the Project constructor, and it will be passed on to CLE. You should look at the CLE API docs. if you want to know everything that could possibly be passed in as an option, but we will go over some important and frequently used options here.

### Basic Options

We’ve discussed `auto_load_libs` already - it enables or disables CLE’s attempt to automatically resolve shared library dependencies, and is on by default. Additionally, there is the opposite, `except_missing_libs`, which, if set to true, will cause an exception to be thrown whenever a binary has a shared library dependency that cannot be resolved.

You can pass a list of strings to `force_load_libs` and anything listed will be treated as an unresolved shared library dependency right out of the gate, or you can pass a list of strings to `skip_libs` to prevent any library of that name from being resolved as a dependency. Additionally, you can pass a list of strings (or a single string) to `ld_path`, which will be used as an additional search path for shared libraries, before any of the defaults: the same directory as the loaded program, the current working directory, and your system libraries.

### Per-Binary Options

If you want to specify some options that only apply to a specific binary object, CLE will let you do that too. The parameters `main_opts` and `lib_opts` do this by taking dictionaries of options. `main_opts` is a mapping from option names to option values, while `lib_opts` is a mapping from library name to dictionaries mapping option names to option values.

The options that you can use vary from backend to backend, but some common ones are:

- `backend` - which backend to use, as either a class or a name

- `base_addr` - a base address to use

- `entry_point` - an entry point to use

- `arch` - the name of an architecture to use

Example:

```
>>> angr.Project('examples/fauxware/fauxware', main_opts={'backend': 'blob', 'arch': 'i386'}, lib_opts={'libc.so.6': {'backend': 'elf'}})
<Project examples/fauxware/fauxware>

```

### Backends

CLE currently has backends for statically loading ELF, PE, CGC, Mach-O and ELF core dump files, as well as loading files into a flat address space. CLE will automatically detect the correct backend to use in most cases, so you shouldn’t need to specify which backend you’re using unless you’re doing some pretty weird stuff.

You can force CLE to use a specific backend for an object by including a key in its options dictionary, as described above. Some backends cannot autodetect which architecture to use and *must* have a `arch` specified. The key doesn’t need to match any list of architectures; angr will identify which architecture you mean given almost any common identifier for any supported arch.

To refer to a backend, use the name from this table:

| backend name

 description

 requires `arch`?

 |
| elf

 Static loader for ELF files based on PyELFTools

 no

 |
| pe

 Static loader for PE files based on PEFile

 no

 |
| mach-o

 Static loader for Mach-O files. Does not support dynamic linking or rebasing.

 no

 |
| cgc

 Static loader for Cyber Grand Challenge binaries

 no

 |
| backedcgc

 Static loader for CGC binaries that allows specifying memory and register backers

 no

 |
| elfcore

 Static loader for ELF core dumps

 no

 |
| blob

 Loads the file into memory as a flat image

 yes

 |

## Symbolic Function Summaries

By default, Project tries to replace external calls to library functions by using symbolic summaries termed *SimProcedures* - effectively just Python functions that imitate the library function’s effect on the state. We’ve implemented a whole bunch of functions as SimProcedures. These builtin procedures are available in the `angr.SIM_PROCEDURES` dictionary, which is two-leveled, keyed first on the package name (libc, posix, win32, stubs) and then on the name of the library function. Executing a SimProcedure instead of the actual library function that gets loaded from your system makes analysis a LOT more tractable, at the cost of some potential inaccuracies.

When no such summary is available for a given function:

- if `auto_load_libs` is `True` (this is the default), then the *real* library function is executed instead. This may or may not be what you want, depending on the actual function. For example, some of libc’s functions are extremely complex to analyze and will most likely cause an explosion of the number of states for the path trying to execute them.

- if `auto_load_libs` is `False`, then external functions are unresolved, and Project will resolve them to a generic “stub” SimProcedure called `ReturnUnconstrained`. It does what its name says: it returns a unique unconstrained symbolic value each time it is called.

- if `use_sim_procedures` (this is a parameter to `angr.Project`, not `cle.Loader`) is `False` (it is `True` by default), then only symbols provided by the extern object will be replaced with SimProcedures, and they will be replaced by a stub `ReturnUnconstrained`, which does nothing but return a symbolic value.

- you may specify specific symbols to exclude from being replaced with SimProcedures with the parameters to `angr.Project`: `exclude_sim_procedures_list` and `exclude_sim_procedures_func`.

- Look at the code for `angr.Project._register_object` for the exact algorithm.

### Hooking

The mechanism by which angr replaces library code with a Python summary is called hooking, and you can do it too! When performing simulation, at every step angr checks if the current address has been hooked, and if so, runs the hook instead of the binary code at that address. The API to let you do this is `proj.hook(addr, hook)`, where `hook` is a SimProcedure instance. You can manage your project’s hooks with `.is_hooked`, `.unhook`, and `.hooked_by`, which should hopefully not require explanation.

There is an alternate API for hooking an address that lets you specify your own off-the-cuff function to use as a hook, by using `proj.hook(addr)` as a function decorator. If you do this, you can also optionally specify a `length` keyword argument to make execution jump some number of bytes forward after your hook finishes.

```
>>> stub_func = angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'] # this is a CLASS
>>> proj.hook(0x10000, stub_func())  # hook with an instance of the class

>>> proj.is_hooked(0x10000)            # these functions should be pretty self-explanitory
True
>>> proj.hooked_by(0x10000)
<ReturnUnconstrained>
>>> proj.unhook(0x10000)

>>> @proj.hook(0x20000, length=5)
... def my_hook(state):
...     state.regs.rax = 1

>>> proj.is_hooked(0x20000)
True

```

Furthermore, you can use `proj.hook_symbol(name, hook)`, providing the name of a symbol as the first argument, to hook the address where the symbol lives. One very important usage of this is to extend the behavior of angr’s built-in library SimProcedures. Since these library functions are just classes, you can subclass them, overriding pieces of their behavior, and then use your subclass in a hook.

## So far so good!

By now, you should have a reasonable understanding of how to control the environment in which your analysis happens, on the level of the CLE loader and the angr Project. You should also understand that angr makes a reasonable attempt to simplify its analysis by hooking complex library functions with SimProcedures that summarize the effects of the functions.

In order to see all the things you can do with the CLE loader and its backends, look at the CLE API docs.

---

## 核心概念：求解引擎（Solver Engine）

angr’s power comes not from it being an emulator, but from being able to execute with what we call *symbolic variables*. Instead of saying that a variable has a *concrete* numerical value, we can say that it holds a *symbol*, effectively just a name. Then, performing arithmetic operations with that variable will yield a tree of operations (termed an *abstract syntax tree* or *AST*, from compiler theory). ASTs can be translated into constraints for an *SMT solver*, like z3, in order to ask questions like *“given the output of this sequence of operations, what must the input have been?”* Here, you’ll learn how to use angr to answer this.

## Working with Bitvectors

Let’s get a dummy project and state so we can start playing with numbers.

```
>>> import angr, monkeyhex
>>> proj = angr.Project('/bin/true')
>>> state = proj.factory.entry_state()

```

A bitvector is just a sequence of bits, interpreted with the semantics of a bounded integer for arithmetic. Let’s make a few.

```
# 64-bit bitvectors with concrete values 1 and 100
>>> one = claripy.BVV(1, 64)
>>> one
 <BV64 0x1>
>>> one_hundred =claripy.BVV(100, 64)
>>> one_hundred
 <BV64 0x64>

# create a 27-bit bitvector with concrete value 9
>>> weird_nine = claripy.BVV(9, 27)
>>> weird_nine
<BV27 0x9>

```

As you can see, you can have any sequence of bits and call them a bitvector. You can do math with them too:

```
>>> one + one_hundred
<BV64 0x65>

# You can provide normal Python integers and they will be coerced to the
appropriate type: >>> one_hundred + 0x100 <BV64 0x164>

# The semantics of normal wrapping arithmetic apply
>>> one_hundred - one*200
<BV64 0xffffffffffffff9c>

```

You *cannot* say `one + weird_nine`, though. It is a type error to perform an operation on bitvectors of differing lengths. You can, however, extend `weird_nine` so it has an appropriate number of bits:

```
>>> weird_nine.zero_extend(64 - 27)
<BV64 0x9>
>>> one + weird_nine.zero_extend(64 - 27)
<BV64 0xa>

```

`zero_extend` will pad the bitvector on the left with the given number of zero bits. You can also use `sign_extend` to pad with a duplicate of the highest bit, preserving the value of the bitvector under two’s complement signed integer semantics.

Now, let’s introduce some symbols into the mix.

```
# Create a bitvector symbol named "x" of length 64 bits
>>> x = claripy.BVS("x", 64)
>>> x
<BV64 x_9_64>
>>> y = claripy.BVS("y", 64)
>>> y
<BV64 y_10_64>

```

`x` and `y` are now *symbolic variables*, which are kind of like the variables you learned to work with in 7th grade algebra. Notice that the name you provided has been mangled by appending an incrementing counter and You can do as much arithmetic as you want with them, but you won’t get a number back, you’ll get an AST instead.

```
>>> x + one
<BV64 x_9_64 + 0x1>

>>> (x + one) / 2
<BV64 (x_9_64 + 0x1) / 0x2>

>>> x - y
<BV64 x_9_64 - y_10_64>

```

Technically `x` and `y` and even `one` are also ASTs - any bitvector is a tree of operations, even if that tree is only one layer deep. To understand this, let’s learn how to process ASTs.

Each AST has a `.op` and a `.args`. The op is a string naming the operation being performed, and the args are the values the operation takes as input. Unless the op is `BVV` or `BVS` (or a few others…), the args are all other ASTs, the tree eventually terminating with BVVs or BVSs.

```
>>> tree = (x + 1) / (y + 2)
>>> tree
<BV64 (x_9_64 + 0x1) / (y_10_64 + 0x2)>
>>> tree.op
'__floordiv__'
>>> tree.args
(<BV64 x_9_64 + 0x1>, <BV64 y_10_64 + 0x2>)
>>> tree.args[0].op
'__add__'
>>> tree.args[0].args
(<BV64 x_9_64>, <BV64 0x1>)
>>> tree.args[0].args[1].op
'BVV'
>>> tree.args[0].args[1].args
(1, 64)

```

From here on out, we will use the word “bitvector” to refer to any AST whose topmost operation produces a bitvector. There can be other data types represented through ASTs, including floating point numbers and, as we’re about to see, booleans.

## Symbolic Constraints

Performing comparison operations between any two similarly-typed ASTs will yield another AST - not a bitvector, but now a symbolic boolean.

```
>>> x == 1
<Bool x_9_64 == 0x1>
>>> x == one
<Bool x_9_64 == 0x1>
>>> x > 2
<Bool x_9_64 > 0x2>
>>> x + y == one_hundred + 5
<Bool (x_9_64 + y_10_64) == 0x69>
>>> one_hundred > 5
<Bool True>
>>> one_hundred > -5
<Bool False>

```

One tidbit you can see from this is that the comparisons are unsigned by default. The -5 in the last example is coerced to `<BV64 0xfffffffffffffffb>`, which is definitely not less than one hundred. If you want the comparison to be signed, you can say `one_hundred.SGT(-5)` (that’s “signed greater-than”). A full list of operations can be found at the end of this chapter.

This snippet also illustrates an important point about working with angr - you should never directly use a comparison between variables in the condition for an if- or while-statement, since the answer might not have a concrete truth value. Even if there is a concrete truth value, `if one > one_hundred` will raise an exception. Instead, you should use `solver.is_true` and `solver.is_false`, which test for concrete truthyness/falsiness without performing a constraint solve.

```
>>> yes = one == 1
>>> no = one == 2
>>> maybe = x == y
>>> state.solver.is_true(yes)
True
>>> state.solver.is_false(yes)
False
>>> state.solver.is_true(no)
False
>>> state.solver.is_false(no)
True
>>> state.solver.is_true(maybe)
False
>>> state.solver.is_false(maybe)
False

```

## Constraint Solving

You can treat any symbolic boolean as an assertion about the valid values of a symbolic variable by adding it as a *constraint* to the state. You can then query for a valid value of a symbolic variable by asking for an evaluation of a symbolic expression.

An example will probably be more clear than an explanation here:

```
>>> state.solver.add(x > y)
>>> state.solver.add(y > 2)
>>> state.solver.add(10 > x)
>>> state.solver.eval(x)
4

```

By adding these constraints to the state, we’ve forced the constraint solver to consider them as assertions that must be satisfied about any values it returns. If you run this code, you might get a different value for x, but that value will definitely be greater than 3 (since y must be greater than 2 and x must be greater than y) and less than 10. Furthermore, if you then say `state.solver.eval(y)`, you’ll get a value of y which is consistent with the value of x that you got. If you don’t add any constraints between two queries, the results will be consistent with each other.

From here, it’s easy to see how to do the task we proposed at the beginning of the chapter - finding the input that produced a given output.

```
# get a fresh state without constraints
>>> state = proj.factory.entry_state()
>>> input = claripy.BVS('input', 64)
>>> operation = (((input + 4) * 3) >> 1) + input
>>> output = 200
>>> state.solver.add(operation == output)
>>> state.solver.eval(input)
0x3333333333333381

```

Note that, again, this solution only works because of the bitvector semantics. If we were operating over the domain of integers, there would be no solutions!

If we add conflicting or contradictory constraints, such that there are no values that can be assigned to the variables such that the constraints are satisfied, the state becomes *unsatisfiable*, or unsat, and queries against it will raise an exception. You can check the satisfiability of a state with `state.satisfiable()`.

```
>>> state.solver.add(input < 2**32)
>>> state.satisfiable()
False

```

You can also evaluate more complex expressions, not just single variables.

```
# fresh state
>>> state = proj.factory.entry_state()
>>> state.solver.add(x - y >= 4)
>>> state.solver.add(y > 0)
>>> state.solver.eval(x)
5
>>> state.solver.eval(y)
1
>>> state.solver.eval(x + y)
6

```

From this we can see that `eval` is a general purpose method to convert any bitvector into a Python primitive while respecting the integrity of the state. This is why we use `eval` to convert from concrete bitvectors to Python ints, too!

Also note that the x and y variables can be used in this new state despite having been created using an old state. Variables are not tied to any one state, and can exist freely.

## Floating point numbers

z3 has support for the theory of IEEE754 floating point numbers, and so angr can use them as well. The main difference is that instead of a width, a floating point number has a *sort*. You can create floating point symbols and values with `FPV` and `FPS`.

```
# fresh state
>>> state = proj.factory.entry_state()
>>> a = claripy.FPV(3.2, claripy.fp.FSORT_DOUBLE)
>>> a
<FP64 FPV(3.2, DOUBLE)>

>>> b = claripy.FPS('b', claripy.fp.FSORT_DOUBLE)
>>> b
<FP64 FPS('FP_b_0_64', DOUBLE)>

>>> a + b
<FP64 fpAdd('RNE', FPV(3.2, DOUBLE), FPS('FP_b_0_64', DOUBLE))>

>>> a + 4.4
<FP64 FPV(7.6000000000000005, DOUBLE)>

>>> b + 2 < 0
<Bool fpLT(fpAdd('RNE', FPS('FP_b_0_64', DOUBLE), FPV(2.0, DOUBLE)), FPV(0.0, DOUBLE))>

```

So there’s a bit to unpack here - for starters the pretty-printing isn’t as smart about floating point numbers. But past that, most operations actually have a third parameter, implicitly added when you use the binary operators - the rounding mode. The IEEE754 spec supports multiple rounding modes (round-to-nearest, round-to-zero, round-to-positive, etc), so z3 has to support them. If you want to specify the rounding mode for an operation, use the fp operation explicitly (`claripy.fpAdd` for example) with a rounding mode (one of `claripy.fp.RM_*`) as the first argument.

Constraints and solving work in the same way, but with `eval` returning a floating point number:

```
>>> state.solver.add(b + 2 < 0)
>>> state.solver.add(b + 2 > -1)
>>> state.solver.eval(b)
-2.4999999999999996

```

This is nice, but sometimes we need to be able to work directly with the representation of the float as a bitvector. You can interpret bitvectors as floats and vice versa, with the methods `raw_to_bv` and `raw_to_fp`:

```
>>> a.raw_to_bv()
<BV64 0x400999999999999a>
>>> b.raw_to_bv()
<BV64 fpToIEEEBV(FPS('FP_b_0_64', DOUBLE))>

>>> claripy.BVV(0, 64).raw_to_fp()
<FP64 FPV(0.0, DOUBLE)>
>>> claripy.BVS('x', 64).raw_to_fp()
<FP64 fpToFP(x_1_64, DOUBLE)>

```

These conversions preserve the bit-pattern, as if you casted a float pointer to an int pointer or vice versa. However, if you want to preserve the value as closely as possible, as if you casted a float to an int (or vice versa), you can use a different set of methods, `val_to_fp` and `val_to_bv`. These methods must take the size or sort of the target value as a parameter, due to the floating-point nature of floats.

```
>>> a
<FP64 FPV(3.2, DOUBLE)>
>>> a.val_to_bv(12)
<BV12 0x3>
>>> a.val_to_bv(12).val_to_fp(claripy.fp.FSORT_FLOAT)
<FP32 FPV(3.0, FLOAT)>

```

These methods can also take a `signed` parameter, designating the signedness of the source or target bitvector.

## More Solving Methods

`eval` will give you one possible solution to an expression, but what if you want several? What if you want to ensure that the solution is unique? The solver provides you with several methods for common solving patterns:

- `solver.eval(expression)` will give you one possible solution to the given expression.

- `solver.eval_one(expression)` will give you the solution to the given expression, or throw an error if more than one solution is possible.

- `solver.eval_upto(expression, n)` will give you up to n solutions to the given expression, returning fewer than n if fewer than n are possible.

- `solver.eval_atleast(expression, n)` will give you n solutions to the given expression, throwing an error if fewer than n are possible.

- `solver.eval_exact(expression, n)` will give you n solutions to the given expression, throwing an error if fewer or more than are possible.

- `solver.min(expression)` will give you the minimum possible solution to the given expression.

- `solver.max(expression)` will give you the maximum possible solution to the given expression.

Additionally, all of these methods can take the following keyword arguments:

- `extra_constraints` can be passed as a tuple of constraints. These constraints will be taken into account for this evaluation, but will not be added to the state.

- `cast_to` can be passed a data type to cast the result to. Currently, this can only be `int` and `bytes`, which will cause the method to return the corresponding representation of the underlying data. For example, `state.solver.eval(claripy.BVV(0x41424344, 32), cast_to=bytes)` will return `b'ABCD'`.

## Summary

That was a lot!! After reading this, you should be able to create and manipulate bitvectors, booleans, and floating point values to form trees of operations, and then query the constraint solver attached to a state for possible solutions under a set of constraints. Hopefully by this point you understand the power of using ASTs to represent computations, and the power of a constraint solver.

In the appendix, you can find a reference for all the additional operations you can apply to ASTs, in case you ever need a quick table to look at.

---

## 核心概念：程序状态（Program State）

So far, we’ve only used angr’s simulated program states (`SimState` objects) in the barest possible way in order to demonstrate basic concepts about angr’s operation. Here, you’ll learn about the structure of a state object and how to interact with it in a variety of useful ways.

## Review: Reading and writing memory and registers

If you’ve been reading this book in order (and you should be, at least for this first section), you already saw the basics of how to access memory and registers. `state.regs` provides read and write access to the registers through attributes with the names of each register, and `state.mem` provides typed read and write access to memory with index-access notation to specify the address followed by an attribute access to specify the type you would like to interpret the memory as.

Additionally, you should now know how to work with ASTs, so you can now understand that any bitvector-typed AST can be stored in registers or memory.

Here are some quick examples for copying and performing operations on data from the state:

```
>>> import angr, claripy
>>> proj = angr.Project('/bin/true')
>>> state = proj.factory.entry_state()

# copy rsp to rbp
>>> state.regs.rbp = state.regs.rsp

# store rdx to memory at 0x1000
>>> state.mem[0x1000].uint64_t = state.regs.rdx

# dereference rbp
>>> state.regs.rbp = state.mem[state.regs.rbp].uint64_t.resolved

# add rax, qword ptr [rsp + 8]
>>> state.regs.rax += state.mem[state.regs.rsp + 8].uint64_t.resolved

```

## Basic Execution

Earlier, we showed how to use a Simulation Manager to do some basic execution. We’ll show off the full capabilities of the simulation manager in the next chapter, but for now we can use a much simpler interface to demonstrate how symbolic execution works: `state.step()`. This method will perform one step of symbolic execution and return an object called `angr.engines.successors.SimSuccessors`. Unlike normal emulation, symbolic execution can produce several successor states that can be classified in a number of ways. For now, what we care about is the `.successors` property of this object, which is a list containing all the “normal” successors of a given step.

Why a list, instead of just a single successor state? Well, angr’s process of symbolic execution is just the taking the operations of the individual instructions compiled into the program and performing them to mutate a SimState. When a line of code like `if (x > 4)` is reached, what happens if x is a symbolic bitvector? Somewhere in the depths of angr, the comparison `x > 4` is going to get performed, and the result is going to be `<Bool x_32_1 > 4>`.

That’s fine, but the next question is, do we take the “true” branch or the “false” one? The answer is, we take both! We generate two entirely separate successor states - one simulating the case where the condition was true and simulating the case where the condition was false. In the first state, we add `x > 4` as a constraint, and in the second state, we add `!(x > 4)` as a constraint. That way, whenever we perform a constraint solve using either of these successor states, *the conditions on the state ensure that any solutions we get are valid inputs that will cause execution to follow the same path that the given state has followed.*

To demonstrate this, let’s use a fake firmware image <../examples/fauxware/fauxware> as an example. If you look at the source code <../examples/fauxware/fauxware.c> for this binary, you’ll see that the authentication mechanism for the firmware is backdoored; any username can be authenticated as an administrator with the password “SOSNEAKY”. Furthermore, the first comparison against user input that happens is the comparison against the backdoor, so if we step until we get more than one successor state, one of those states will contain conditions constraining the user input to be the backdoor password. The following snippet implements this:

```
>>> proj = angr.Project('examples/fauxware/fauxware')
>>> state = proj.factory.entry_state(stdin=angr.SimFile)  # ignore that argument for now - we're disabling a more complicated default setup for the sake of education
>>> while True:
...     succ = state.step()
...     if len(succ.successors) == 2:
...         break
...     state = succ.successors[0]

>>> state1, state2 = succ.successors
>>> state1
<SimState @ 0x400629>
>>> state2
<SimState @ 0x400699

```

Don’t look at the constraints on these states directly - the branch we just went through involves the result of `strcmp`, which is a tricky function to emulate symbolically, and the resulting constraints are *very* complicated.

The program we emulated took data from standard input, which angr treats as an infinite stream of symbolic data by default. To perform a constraint solve and get a possible value that input could have taken in order to satisfy the constraints, we’ll need to get a reference to the actual contents of stdin. We’ll go over how our file and input subsystems work later on this very page, but for now, just use `state.posix.stdin.load(0, state.posix.stdin.size)` to retrieve a bitvector representing all the content read from stdin so far.

```
>>> input_data = state1.posix.stdin.load(0, state1.posix.stdin.size)

>>> state1.solver.eval(input_data, cast_to=bytes)
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00\x00\x00'

>>> state2.solver.eval(input_data, cast_to=bytes)
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00S\x00\x80N\x00\x00 \x00\x00\x00\x00'

```

As you can see, in order to go down the `state1` path, you must have given as a password the backdoor string “SOSNEAKY”. In order to go down the `state2` path, you must have given something *besides* “SOSNEAKY”. z3 has helpfully provided one of the billions of strings fitting this criteria.

Fauxware was the first program angr’s symbolic execution ever successfully worked on, back in 2013. By finding its backdoor using angr you are participating in a grand tradition of having a bare-bones understanding of how to use symbolic execution to extract meaning from binaries!

## State Presets

So far, whenever we’ve been working with a state, we’ve created it with `project.factory.entry_state()`. This is just one of several *state constructors* available on the project factory:

- `.blank_state()` constructs a “blank slate” blank state, with most of its data left uninitialized. When accessing uninitialized data, an unconstrained symbolic value will be returned.

- `.entry_state()` constructs a state ready to execute at the main binary’s entry point.

- `.full_init_state()` constructs a state that is ready to execute through any initializers that need to be run before the main binary’s entry point, for example, shared library constructors or preinitializers. When it is finished with these it will jump to the entry point.

- `.call_state()` constructs a state ready to execute a given function.

You can customize the state through several arguments to these constructors:

- All of these constructors can take an `addr` argument to specify the exact address to start.

- If you’re executing in an environment that can take command line arguments or an environment, you can pass a list of arguments through `args` and a dictionary of environment variables through `env` into `entry_state` and `full_init_state`. The values in these structures can be strings or bitvectors, and will be serialized into the state as the arguments and environment to the simulated execution. The default `args` is an empty list, so if the program you’re analyzing expects to find at least an `argv[0]`, you should always provide that!

- If you’d like to have `argc` be symbolic, you can pass a symbolic bitvector as `argc` to the `entry_state` and `full_init_state` constructors. Be careful, though: if you do this, you should also add a constraint to the resulting state that your value for argc cannot be larger than the number of args you passed into `args`.

- To use the call state, you should call it with `.call_state(addr, arg1, arg2,...)`, where `addr` is the address of the function you want to call and `argN` is the Nth argument to that function, either as a Python integer, string, or array, or a bitvector. If you want to have memory allocated and actually pass in a pointer to an object, you should wrap it in an PointerWrapper, i.e. `angr.PointerWrapper("point to me!")`. The results of this API can be a little unpredictable, but we’re working on it.

- To specify the calling convention used for a function with `call_state`, you can pass a `SimCC` instance as the `cc` argument. We try to pick a sane default, but for special cases you will need to help angr out.

There are several more options that can be used in any of these constructors! See the docs on the `project.factory` object (an `angr.factory.AngrObjectFactory`) for more details.

## Low level interface for memory

The `state.mem` interface is convenient for loading typed data from memory, but when you want to do raw loads and stores to and from ranges of memory, it’s very cumbersome. It turns out that `state.mem` is actually just a bunch of logic to correctly access the underlying memory storage, which is just a flat address space filled with bitvector data: `state.memory`. You can use `state.memory` directly with the `.load(addr, size)` and `.store(addr,val)` methods:

```
>>> s = proj.factory.blank_state()
>>> s.memory.store(0x4000, claripy.BVV(0x0123456789abcdef0123456789abcdef, 128))
>>> s.memory.load(0x4004, 6) # load-size is in bytes
<BV48 0x89abcdef0123>

```

As you can see, the data is loaded and stored in a “big-endian” fashion, since the primary purpose of `state.memory` is to load an store swaths of data with no attached semantics. However, if you want to perform a byteswap on the loaded or stored data, you can pass a keyword argument `endness` - if you specify little-endian, byteswap will happen. The endness should be one of the members of the `Endness` enum in the `archinfo` package used to hold declarative data about CPU architectures for angr. Additionally, the endness of the program being analyzed can be found as `arch.memory_endness` - for instance `state.arch.memory_endness`.

```
>>> import archinfo
>>> s.memory.load(0x4000, 4, endness=archinfo.Endness.LE)
<BV32 0x67452301>

```

There is also a low-level interface for register access, `state.registers`, that uses the exact same API as `state.memory`, but explaining its behavior involves a dive into the abstractions that angr uses to seamlessly work with multiple architectures. The short version is that it is simply a register file, with the mapping between registers and offsets defined in archinfo.

## State Options

There are a lot of little tweaks that can be made to the internals of angr that will optimize behavior in some situations and be a detriment in others. These tweaks are controlled through state options.

On each SimState object, there is a set (`state.options`) of all its enabled options. Each option (really just a string) controls the behavior of angr’s execution engine in some minute way. A listing of the full domain of options, along with the defaults for different state types, can be found in the appendix. You can access an individual option for adding to a state through `angr.options`. The individual options are named with CAPITAL_LETTERS, but there are also common groupings of objects that you might want to use bundled together, named with lowercase_letters.

When creating a SimState through any constructor, you may pass the keyword arguments `add_options` and `remove_options`, which should be sets of options that modify the initial options set from the default.

```
# Example: enable lazy solves, an option that causes state satisfiability to be checked as infrequently as possible.
# This change to the settings will be propagated to all successor states created from this state after this line.
>>> s.options.add(angr.options.LAZY_SOLVES)

# Create a new state with lazy solves enabled
>>> s = proj.factory.entry_state(add_options={angr.options.LAZY_SOLVES})

# Create a new state without simplification options enabled
>>> s = proj.factory.entry_state(remove_options=angr.options.simplification)

```

## State Plugins

With the exception of the set of options just discussed, everything stored in a SimState is actually stored in a *plugin* attached to the state. Almost every property on the state we’ve discussed so far is a plugin - `memory`, `registers`, `mem`, `regs`, `solver`, etc. This design allows for code modularity as well as the ability to easily implement new kinds of data storage for other aspects of an emulated state, or the ability to provide alternate implementations of plugins.

For example, the normal `memory` plugin simulates a flat memory space, but analyses can choose to enable the “abstract memory” plugin, which uses alternate data types for addresses to simulate free-floating memory mappings independent of address, to provide `state.memory`. Conversely, plugins can reduce code complexity: `state.memory` and `state.registers` are actually two different instances of the same plugin, since the registers are emulated with an address space as well.

### The globals plugin

`state.globals` is an extremely simple plugin: it implements the interface of a standard Python dict, allowing you to store arbitrary data on a state.

### The history plugin

`state.history` is a very important plugin storing historical data about the path a state has taken during execution. It is actually a linked list of several history nodes, each one representing a single round of execution—you can traverse this list with `state.history.parent.parent` etc.

To make it more convenient to work with this structure, the history also provides several efficient iterators over the history of certain values. In general, these values are stored as `history.recent_NAME` and the iterator over them is just `history.NAME`. For example, `for addr instate.history.bbl_addrs: print hex(addr)` will print out a basic block address trace for the binary, while `state.history.recent_bbl_addrs` is the list of basic blocks executed in the most recent step, `state.history.parent.recent_bbl_addrs` is the list of basic blocks executed in the previous step, etc. If you ever need to quickly obtain a flat list of these values, you can access `.hardcopy`, e.g. `state.history.bbl_addrs.hardcopy`. Keep in mind though, index-based accessing is implemented on the iterators.

Here is a brief listing of some of the values stored in the history:

- `history.descriptions` is a listing of string descriptions of each of the rounds of execution performed on the state.

- `history.bbl_addrs` is a listing of the basic block addresses executed by the state. There may be more than one per round of execution, and not all addresses may correspond to binary code - some may be addresses at which SimProcedures are hooked.

- `history.jumpkinds` is a listing of the disposition of each of the control flow transitions in the state’s history, as VEX enum strings.

- `history.jump_guards` is a listing of the conditions guarding each of the branches that the state has encountered.

- `history.events` is a semantic listing of “interesting events” which happened during execution, such as the presence of a symbolic jump condition, the program popping up a message box, or execution terminating with an exit code.

- `history.actions` is usually empty, but if you add the `angr.options.refs` options to the state, it will be populated with a log of all the memory, register, and temporary value accesses performed by the program.

### The callstack plugin

angr will track the call stack for the emulated program. On every call instruction, a frame will be added to the top of the tracked callstack, and whenever the stack pointer drops below the point where the topmost frame was called, a frame is popped. This allows angr to robustly store data local to the current emulated function.

Similar to the history, the callstack is also a linked list of nodes, but there are no provided iterators over the contents of the nodes - instead you can directly iterate over `state.callstack` to get the callstack frames for each of the active frames, in order from most recent to oldest. If you just want the topmost frame, this is `state.callstack`.

- `callstack.func_addr` is the address of the function currently being executed

- `callstack.call_site_addr` is the address of the basic block which called the current function

- `callstack.stack_ptr` is the value of the stack pointer from the beginning of the current function

- `callstack.ret_addr` is the location that the current function will return to if it returns

## More about I/O: Files, file systems, and network sockets

Please refer to Working with File System, Sockets, and Pipes for a more complete and detailed documentation of how I/O is modeled in angr.

## Copying and Merging

A state supports very fast copies, so that you can explore different possibilities:

```
>>> proj = angr.Project('/bin/true')
>>> s = proj.factory.blank_state()
>>> s1 = s.copy()
>>> s2 = s.copy()

>>> s1.mem[0x1000].uint32_t = 0x41414141
>>> s2.mem[0x1000].uint32_t = 0x42424242

```

States can also be merged together.

```
# merge will return a tuple. the first element is the merged state
# the second element is a symbolic variable describing a state flag
# the third element is a boolean describing whether any merging was done
>>> (s_merged, m, anything_merged) = s1.merge(s2)

# this is now an expression that can resolve to "AAAA" *or* "BBBB"
>>> aaaa_or_bbbb = s_merged.mem[0x1000].uint32_t

```

> > **Todo**

describe limitations of merging

---

## API 参考：angr.project（Project）

### `load_shellcode(shellcode, arch, start_offset=0, load_address=0, thumb=False, **kwargs)`

Load a new project based on a snippet of assembly or bytecode.

**Parameters:**

- **shellcode** (`bytes` | `str`) – The data to load, as either a bytestring of instructions or a string of assembly text

- **arch** – The name of the arch to use, or an archinfo class

- **start_offset** – The offset into the data to start analysis (default 0)

- **load_address** – The address to place the data in memory (default 0)

- **thumb** – Whether this is ARM Thumb shellcode

### `Project`

Bases: `object`

This is the main class of the angr module. It is meant to contain a set of binaries and the relationships between them, and perform analyses on them.

**Parameters:**

- **thing** – The path to the main executable object to analyze, or a CLE Loader object.

- **default_analysis_mode** – The mode of analysis to use by default. Defaults to ‘symbolic’.

- **ignore_functions** – A list of function names that, when imported from shared libraries, should never be stepped into in analysis (calls will return an unconstrained value).

- **use_sim_procedures** – Whether to replace resolved dependencies for which simprocedures are available with said simprocedures.

- **exclude_sim_procedures_func** – A function that, when passed a function name, returns whether or not to wrap it with a simprocedure.

- **exclude_sim_procedures_list** – A list of functions to *not* wrap with simprocedures.

- **arch** – The target architecture (auto-detected otherwise).

- **simos** – a SimOS class to use for this project.

- **engine** – The SimEngine class to use for this project.

- **translation_cache** (*bool*) – If True, cache translated basic blocks rather than re-translating them.

- **selfmodifying_code** (`bool`) – Whether we aggressively support self-modifying code. When enabled, emulation will try to read code from the current state instead of the original memory, regardless of the current memory protections.

- **store_function** – A function that defines how the Project should be stored. Default to pickling.

- **load_function** – A function that defines how the Project should be loaded. Default to unpickling.

- **analyses_preset** (*angr.misc.PluginPreset*) – The plugin preset for the analyses provider (i.e. Analyses instance).

Any additional keyword arguments passed will be passed onto `cle.Loader`.

**Variables:**

- **analyses** – The available analyses.

- **entry** – The program entrypoint.

- **factory** – Provides access to important analysis elements such as path groups and symbolic execution results.

- **filename** – The filename of the executable.

- **loader** – The program loader.

- **storage** – Dictionary of things that should be loaded/stored with the Project.

#### `Project.__init__(thing, default_analysis_mode=None, ignore_functions=None, use_sim_procedures=True, exclude_sim_procedures_func=None, exclude_sim_procedures_list=(), arch=None, simos=None, engine=None, load_options=None, translation_cache=True, selfmodifying_code=False, support_selfmodifying_code=None, store_function=None, load_function=None, analyses_preset=None, concrete_target=None, eager_ifunc_resolution=None, cache_limits=None, rustc_version=None, rustc_optimization_level=None, **kwargs)`

**Parameters:**

- **load_options** (*dict**[**str**, **Any**] **| **None*)

- **selfmodifying_code** (*bool*)

- **support_selfmodifying_code** (*bool** | **None*)

- **cache_limits** (*dict**[**str**, **int** | **None**] **| **None*)

#### `arch: Arch`

#### `llm_client`

The LLM client for this project. Lazy-initialized from environment variables on first access. Set manually via `project.llm_client = LLMClient(...)` or configure via environment variables `ANGR_LLM_MODEL`, `ANGR_LLM_API_KEY`, `ANGR_LLM_API_BASE`.

#### `kb`

#### `Project.get_kb(name)`

#### `analyses: AnalysesHubWithDefault`

#### `Project.hook(addr, hook=None, length=0, kwargs=None, replace=False)`

Hook a section of code with a custom function. This is used internally to provide symbolic summaries of library functions, and can be used to instrument execution or to modify control flow.

When hook is not specified, it returns a function decorator that allows easy hooking. Usage:

```
# Assuming proj is an instance of angr.Project, we will add a custom hook at the entry
# point of the project.
@proj.hook(proj.entry)
def my_hook(state):
    print("Welcome to execution!")

```

**Parameters:**

- **addr** – The address to hook.

- **hook** – A `angr.project.Hook` describing a procedure to run at the given address. You may also pass in a SimProcedure class or a function directly and it will be wrapped in a Hook object for you.

- **length** – If you provide a function for the hook, this is the number of bytes that will be skipped by executing the hook by default.

- **kwargs** – If you provide a SimProcedure for the hook, these are the keyword arguments that will be passed to the procedure’s run method eventually.

- **replace** (`bool` | `None`) – Control the behavior on finding that the address is already hooked. If true, silently replace the hook. If false (default), warn and do not replace the hook. If none, warn and replace the hook.

#### `Project.is_hooked(addr)`

Returns True if addr is hooked.

**Parameters:**

**addr** – An address.

**Return type:**

`bool`

**Returns:**

True if addr is hooked, False otherwise.

#### `Project.hooked_by(addr)`

Returns the current hook for addr.

**Parameters:**

**addr** – An address.

**Return type:**

`SimProcedure` | `None`

**Returns:**

None if the address is not hooked.

#### `Project.unhook(addr)`

Remove a hook.

**Parameters:**

**addr** – The address of the hook.

#### `Project.hook_symbol(symbol_name, simproc, kwargs=None, replace=None)`

Resolve a dependency in a binary. Looks up the address of the given symbol, and then hooks that address. If the symbol was not available in the loaded libraries, this address may be provided by the CLE externs object.

Additionally, if instead of a symbol name you provide an address, some secret functionality will kick in and you will probably just hook that address, UNLESS you’re on powerpc64 ABIv1 or some yet-unknown scary ABI that has its function pointers point to something other than the actual functions, in which case it’ll do the right thing.

**Parameters:**

- **symbol_name** – The name of the dependency to resolve.

- **simproc** – The SimProcedure instance (or function) with which to hook the symbol

- **kwargs** – If you provide a SimProcedure for the hook, these are the keyword arguments that will be passed to the procedure’s run method eventually.

- **replace** (`bool` | `None`) – Control the behavior on finding that the address is already hooked. If true, silently replace the hook. If false, warn and do not replace the hook. If none (default), warn and replace the hook.

**Returns:**

The address of the new symbol.

**Return type:**

int

#### `Project.symbol_hooked_by(symbol_name)`

Return the SimProcedure, if it exists, for the given symbol name.

**Parameters:**

**symbol_name** (*str*) – Name of the symbol.

**Return type:**

`SimProcedure` | `None`

**Returns:**

None if the address is not hooked.

#### `Project.is_symbol_hooked(symbol_name)`

Check if a symbol is already hooked.

**Parameters:**

**symbol_name** (*str*) – Name of the symbol.

**Returns:**

True if the symbol can be resolved and is hooked, False otherwise.

**Return type:**

bool

#### `Project.unhook_symbol(symbol_name)`

Remove the hook on a symbol. This function will fail if the symbol is provided by the extern object, as that would result in a state where analysis would be unable to cope with a call to this symbol.

#### `Project.rehook_symbol(new_address, symbol_name, stubs_on_sync)`

Move the hook for a symbol to a specific address :type new_address: :param new_address: the new address that will trigger the SimProc execution :type symbol_name: :param symbol_name: the name of the symbol (f.i. strcmp ) :return: None

#### `Project.execute(*args, **kwargs)`

This function is a symbolic execution helper in the simple style supported by triton and manticore. It designed to be run after setting up hooks (see Project.hook), in which the symbolic state can be checked.

This function can be run in three different ways:

> - When run with no parameters, this function begins symbolic execution from the entrypoint.

- It can also be run with a “state” parameter specifying a SimState to begin symbolic execution from.

- Finally, it can accept any arbitrary keyword arguments, which are all passed to project.factory.full_init_state.

If symbolic execution finishes, this function returns the resulting simulation manager.

#### `Project.terminate_execution()`

Terminates a symbolic execution that was started with Project.execute().

#### `Project.languages()`

**Return type:**

`list`[`str`]

#### `is_rust_binary: bool`

#### `Project.get_function_cache_limit()`

Get the cache limit for function-level caches.

**Return type:**

`int` | `None`

**Returns:**

The cache limit, or None for disabling the cache.

#### `Project.get_cfg_node_cache_limit()`

Get the cache limit for CFG node caches.

**Return type:**

`int` | `None`

**Returns:**

The cache limit, or None to disable the cache.

#### `Project.get_cfg_edge_cache_limit()`

Get the cache limit for CFG edge caches (adjacency data spilling).

**Return type:**

`int` | `None`

**Returns:**

The cache limit, or None to disable the cache.

---

## API 参考：angr.factory

### `AngrObjectFactory`

Bases: `object`

This factory provides access to important analysis elements.

#### `AngrObjectFactory.__init__(project, default_engine=None)`

**Parameters:**

**default_engine** (*type**[**SimEngine**] **| **None*)

#### `default_engine_factory: type[SimEngine]`

#### `project: Project`

#### `procedure_engine: ProcedureEngine`

#### `default_engine`

#### `AngrObjectFactory.snippet(addr, jumpkind=None, **block_opts)`

#### `AngrObjectFactory.successors(*args, engine=None, **kwargs)`

Perform execution using an engine. Generally, return a SimSuccessors object classifying the results of the run.

**Parameters:**

- **state** – The state to analyze

- **engine** – The engine to use. If not provided, will use the project default.

- **addr** – optional, an address to execute at instead of the state’s ip

- **jumpkind** – optional, the jumpkind of the previous exit

- **inline** – This is an inline execution. Do not bother copying the state.

Additional keyword arguments will be passed directly into each engine’s process method.

#### `AngrObjectFactory.blank_state(**kwargs)`

Returns a mostly-uninitialized state object. All parameters are optional.

**Parameters:**

- **addr** – The address the state should start at instead of the entry point.

- **initial_prefix** – If this is provided, all symbolic registers will hold symbolic values with names prefixed by this string.

- **fs** – A dictionary of file names with associated preset SimFile objects.

- **concrete_fs** – bool describing whether the host filesystem should be consulted when opening files.

- **chroot** – A path to use as a fake root directory, Behaves similarly to a real chroot. Used only when concrete_fs is set to True.

- **kwargs** – Any additional keyword args will be passed to the SimState constructor.

**Returns:**

The blank state.

**Return type:**

SimState

#### `AngrObjectFactory.entry_state(**kwargs)`

Returns a state object representing the program at its entry point. All parameters are optional.

**Parameters:**

- **addr** – The address the state should start at instead of the entry point.

- **initial_prefix** – If this is provided, all symbolic registers will hold symbolic values with names prefixed by this string.

- **fs** – a dictionary of file names with associated preset SimFile objects.

- **concrete_fs** – boolean describing whether the host filesystem should be consulted when opening files.

- **chroot** – a path to use as a fake root directory, behaves similar to a real chroot. used only when concrete_fs is set to True.

- **argc** – a custom value to use for the program’s argc. May be either an int or a bitvector. If not provided, defaults to the length of args.

- **args** – a list of values to use as the program’s argv. May be mixed strings and bitvectors.

- **env** – a dictionary to use as the environment for the program. Both keys and values may be mixed strings and bitvectors.

**Returns:**

The entry state.

**Return type:**

`SimState`

#### `AngrObjectFactory.full_init_state(**kwargs)`

Very much like `entry_state()`, except that instead of starting execution at the program entry point, execution begins at a special SimProcedure that plays the role of the dynamic loader, calling each of the initializer functions that should be called before execution reaches the entry point.

It can take any of the arguments that can be provided to `entry_state`, except for `addr`.

#### `AngrObjectFactory.call_state(addr, *args, **kwargs)`

Returns a state object initialized to the start of a given function, as if it were called with given parameters.

**Parameters:**

- **addr** – The address the state should start at instead of the entry point.

- **args** – Any additional positional arguments will be used as arguments to the function call.

- **base_state** – Use this SimState as the base for the new state instead of a blank state.

- **cc** – Optionally provide a SimCC object to use a specific calling convention.

- **ret_addr** – Use this address as the function’s return target.

- **stack_base** – An optional pointer to use as the top of the stack, circa the function entry point

- **alloc_base** – An optional pointer to use as the place to put excess argument data

- **grow_like_stack** – When allocating data at alloc_base, whether to allocate at decreasing addresses

- **toc** – The address of the table of contents for ppc64

- **initial_prefix** – If this is provided, all symbolic registers will hold symbolic values with names prefixed by this string.

- **fs** – A dictionary of file names with associated preset SimFile objects.

- **concrete_fs** – bool describing whether the host filesystem should be consulted when opening files.

- **chroot** – A path to use as a fake root directory, Behaves similarly to a real chroot. Used only when concrete_fs is set to True.

- **kwargs** – Any additional keyword args will be passed to the SimState constructor.

**Returns:**

The state at the beginning of the function.

**Return type:**

SimState

The idea here is that you can provide almost any kind of python type in args and it’ll be translated to a binary format to be placed into simulated memory. Lists (representing arrays) must be entirely elements of the same type and size, while tuples (representing structs) can be elements of any type and size. If you’d like there to be a pointer to a given value, wrap the value in a SimCC.PointerWrapper. Any value that can’t fit in a register will be automatically put in a PointerWrapper.

If stack_base is not provided, the current stack pointer will be used, and it will be updated. If alloc_base is not provided, the current stack pointer will be used, and it will be updated. You might not like the results if you provide stack_base but not alloc_base.

grow_like_stack controls the behavior of allocating data at alloc_base. When data from args needs to be wrapped in a pointer, the pointer needs to point somewhere, so that data is dumped into memory at alloc_base. If you set alloc_base to point to somewhere other than the stack, set grow_like_stack to False so that sequential allocations happen at increasing addresses.

#### `AngrObjectFactory.simulation_manager(thing=None, **kwargs)`

Constructs a new simulation manager.

**Parameters:**

- **thing** (`list`[`SimState`] | `SimState` | `None`) – What to put in the new SimulationManager’s active stash (either a SimState or a list of SimStates).

- **kwargs** – Any additional keyword arguments will be passed to the SimulationManager constructor

**Returns:**

The new SimulationManager

**Return type:**

`SimulationManager`

Many different types can be passed to this method:

- If nothing is passed in, the SimulationManager is seeded with a state initialized for the program entry point, i.e. `entry_state()`.

- If a `SimState` is passed in, the SimulationManager is seeded with that state.

- If a list is passed in, the list must contain only SimStates and the whole list will be used to seed the SimulationManager.

#### `AngrObjectFactory.simgr(*args, **kwargs)`

Alias for simulation_manager to save our poor fingers

#### `AngrObjectFactory.callable(addr, prototype=None, concrete_only=False, perform_merge=True, base_state=None, toc=None, cc=None, add_options=None, remove_options=None, techniques=None, step_limit=None)`

A Callable is a representation of a function in the binary that can be interacted with like a native python function.

**Parameters:**

- **addr** (`int` | `Function`) – The address of the function to use. If you pass in the function object, we will take its addr.

- **prototype** – The prototype of the call to use, as a string or a SimTypeFunction

- **concrete_only** – Throw an exception if the execution splits into multiple states

- **perform_merge** – Merge all result states into one at the end (only relevant if concrete_only=False)

- **base_state** – The state from which to do these runs

- **toc** – The address of the table of contents for ppc64

- **cc** – The SimCC to use for a calling convention

- **step_limit** (`int` | `None`) – The maximum number of blocks that Callable will execute before pruning the path.

- **techniques** (*list**[**ExplorationTechnique**] **| **None*)

**Returns:**

A Callable object that can be used as a interface for executing guest code like a python function.

**Return type:**

angr.callable.Callable

#### `AngrObjectFactory.cc()`

Return a SimCC (calling convention) parameterized for this project.

Relevant subclasses of SimFunctionArgument are SimRegArg and SimStackArg, and shortcuts to them can be found on this cc object.

For stack arguments, offsets are relative to the stack pointer on function entry.

#### `AngrObjectFactory.function_prototype()`

Return a default function prototype parameterized for this project and SimOS.

#### `AngrObjectFactory.block(addr, size=None, max_size=None, byte_string=None, thumb=False, backup_state=None, extra_stop_points=None, opt_level=None, num_inst=None, traceflags=0, insn_bytes=None, strict_block_end=None, collect_data_refs=False, cross_insn_opt=True, load_from_ro_regions=False, const_prop=False, initial_regs=None, skip_stmts=False)`

**Overloads:**

- **self**, **addr** (int), **size**, **max_size**, **byte_string**, **thumb**, **backup_state**, **extra_stop_points**, **opt_level**, **num_inst**, **traceflags**, **insn_bytes**, **strict_block_end**, **collect_data_refs**, **cross_insn_opt**, **load_from_ro_regions**, **const_prop**, **initial_regs**, **skip_stmts** → Block

- **self**, **addr** (SootAddressDescriptor), **size**, **max_size**, **byte_string**, **thumb**, **backup_state**, **extra_stop_points**, **opt_level**, **num_inst**, **traceflags**, **insn_bytes**, **strict_block_end**, **collect_data_refs**, **load_from_ro_regions**, **const_prop**, **cross_insn_opt**, **skip_stmts** → SootBlock

#### `AngrObjectFactory.fresh_block(addr, size, backup_state=None)`

---

## API 参考：angr.sim_state（SimState）

### `arch_overridable(f)`

### `SimState`

Bases: `PluginHub`[`SimStatePlugin`], `Generic`

The SimState represents the state of a program, including its memory, registers, and so forth.

**Parameters:**

- **project** (`Project` | `None`) – The project instance.

- **arch** (`Arch` | `None`) – The architecture of the state.

**Variables:**

- **regs** – A convenient view of the state’s registers, where each register is a property

- **mem** – A convenient view of the state’s memory, a `angr.state_plugins.view.SimMemView`

- **registers** – The state’s register file as a flat memory region

- **memory** – The state’s memory as a flat memory region

- **solver** – The symbolic solver and variable manager for this state

- **inspect** – The breakpoint manager, a `angr.state_plugins.inspect.SimInspector`

- **log** – Information about the state’s history

- **scratch** – Information about the current execution step

- **posix** – MISNOMER: information about the operating system or environment model

- **fs** – The current state of the simulated filesystem

- **libc** – Information about the standard library we are emulating

- **cgc** – Information about the cgc environment

- **uc_manager** – Control of under-constrained symbolic execution

- **unicorn** – Control of the Unicorn Engine

#### `solver: SimSolver`

#### `posix: SimSystemPosix`

#### `registers: DefaultMemory`

#### `regs: SimRegNameView`

#### `memory: DefaultMemory`

#### `callstack: CallStack`

#### `mem: SimMemView`

#### `history: SimStateHistory`

#### `inspect: SimInspector`

#### `jni_references: SimStateJNIReferences`

#### `scratch: SimStateScratch`

#### `heap: SimHeapBase`

#### `SimState.__init__(project=None, arch=None, plugins=None, mode=None, options=None, add_options=None, remove_options=None, special_memory_filler=None, os_name=None, plugin_preset='default', cle_memory_backer=None, dict_memory_backer=None, permissions_map=None, default_permissions=3, stack_perms=None, stack_end=None, stack_size=None, regioned_memory_cls=None, **kwargs)`

**Parameters:**

- **project** (*Project** | **None*)

- **arch** (*Arch** | **None*)

- **plugins** (*dict**[**str**, **SimStatePlugin**] **| **None*)

- **mode** (*str** | **None*)

- **options** (*set**[**str**] **| **list**[**str**] **| **SimStateOptions** | **None*)

- **add_options** (*set**[**str**] **| **None*)

- **remove_options** (*set**[**str**] **| **None*)

- **special_memory_filler** (*Callable**[**[**str**, **int**, **int**, **SimState**]**, **Any**] **| **None*)

- **os_name** (*str** | **None*)

- **plugin_preset** (*str*)

- **cle_memory_backer** (*Clemory** | **None*)

- **dict_memory_backer** (*dict**[**int**, **bytes**] **| **None*)

- **permissions_map** (*dict**[**tuple**[**int**, **int**]**, **int**] **| **None*)

- **default_permissions** (*int*)

- **stack_perms** (*int** | **None*)

- **stack_end** (*int** | **None*)

- **stack_size** (*int** | **None*)

#### `plugins`

#### `ip`

Get the instruction pointer expression, trigger SimInspect breakpoints, and generate SimActions. Use `_ip` to not trigger breakpoints or generate actions.

**Returns:**

an expression

#### `addr: IPTypeConc`

Get the concrete address of the instruction pointer, without triggering SimInspect breakpoints or generating SimActions. An integer is returned, or an exception is raised if the instruction pointer is symbolic.

**Returns:**

an int

#### `arch: Arch`

#### `javavm_memory`

In case of an JavaVM with JNI support, a state can store the memory plugin twice; one for the native and one for the java view of the state.

**Returns:**

The JavaVM view of the memory plugin.

#### `javavm_registers`

In case of an JavaVM with JNI support, a state can store the registers plugin twice; one for the native and one for the java view of the state.

**Returns:**

The JavaVM view of the registers plugin.

#### `SimState.simplify(*args)`

Simplify this state’s constraints.

#### `SimState.add_constraints(*constraints)`

Add some constraints to the state.

You may pass in any number of symbolic booleans as variadic positional arguments.

#### `SimState.satisfiable(**kwargs)`

Whether the state’s constraints are satisfiable

#### `SimState.downsize()`

Clean up after the solver engine. Calling this when a state no longer needs to be solved on will reduce memory usage.

#### `SimState.step(**kwargs)`

Perform a step of symbolic execution using this state. Any arguments to AngrObjectFactory.successors can be passed to this.

**Returns:**

A SimSuccessors object categorizing the results of the step.

#### `SimState.block(*args, **kwargs)`

Represent the basic block at this state’s instruction pointer. Any arguments to AngrObjectFactory.block can ba passed to this.

**Returns:**

A Block object describing the basic block of code at this point.

#### `SimState.copy()`

Returns a copy of the state.

#### `SimState.merge(*others, **kwargs)`

Merges this state with the other states. Returns the merging result, merged state, and the merge flag.

**Parameters:**

- **states** – the states to merge

- **merge_conditions** – a tuple of the conditions under which each state holds

- **common_ancestor** – a state that represents the common history between the states being merged. Usually it is only available when EFFICIENT_STATE_MERGING is enabled, otherwise weak-refed states might be dropped from state history instances.

- **plugin_whitelist** – a list of plugin names that will be merged. If this option is given and is not None, any plugin that is not inside this list will not be merged, and will be created as a fresh instance in the new state.

- **common_ancestor_history** – a SimStateHistory instance that represents the common history between the states being merged. This is to allow optimal state merging when EFFICIENT_STATE_MERGING is disabled.

**Returns:**

(merged state, merge flag, a bool indicating if any merging occurred)

#### `SimState.reg_concrete(*args, **kwargs)`

Returns the contents of a register but, if that register is symbolic, raises a SimValueError.

#### `SimState.mem_concrete(*args, **kwargs)`

Returns the contents of a memory but, if the contents are symbolic, raises a SimValueError.

#### `SimState.stack_push(thing)`

Push ‘thing’ to the stack, writing the thing to memory and adjusting the stack pointer.

#### `SimState.stack_pop()`

Pops from the stack and returns the popped thing. The length will be the architecture word size.

#### `SimState.stack_read(offset, length, bp=False)`

Reads length bytes, at an offset into the stack.

**Parameters:**

- **offset** – The offset from the stack pointer.

- **length** – The number of bytes to read.

- **bp** – If True, offset from the BP instead of the SP. Default: False.

#### `SimState.make_concrete_int(expr)`

#### `SimState.dbg_print_stack(depth=None, sp=None)`

Only used for debugging purposes. Return the current stack info in formatted string. If depth is None, the current stack frame (from sp to bp) will be printed out.

#### `SimState.set_mode(mode)`

#### `thumb`

---

## API 参考：angr.sim_manager（SimulationManager）

### `SimulationManager`

Bases: `object`

The Simulation Manager is the future future.

Simulation managers allow you to wrangle multiple states in a slick way. States are organized into “stashes”, which you can step forward, filter, merge, and move around as you wish. This allows you to, for example, step two different stashes of states at different rates, then merge them together.

Stashes can be accessed as attributes (i.e. .active). A mulpyplexed stash can be retrieved by prepending the name with mp_, e.g. .mp_active. A single state from the stash can be retrieved by prepending the name with one_, e.g. .one_active.

Note that you shouldn’t usually be constructing SimulationManagers directly - there is a convenient shortcut for creating them in `Project.factory`: see `angr.factory.AngrObjectFactory`.

The most important methods you should look at are `step`, `explore`, and `use_technique`.

**Parameters:**

- **project** (*angr.project.Project*) – A Project instance.

- **stashes** – A dictionary to use as the stash store.

- **active_states** – Active states to seed the “active” stash with.

- **hierarchy** – A StateHierarchy object to use to track the relationships between states.

- **resilience** – A set of errors to catch during stepping to put a state in the `errore` list. You may also provide the values False, None (default), or True to catch, respectively, no errors, all angr-specific errors, and a set of many common errors.

- **save_unsat** – Set to True in order to introduce unsatisfiable states into the `unsat` stash instead of discarding them immediately.

- **auto_drop** – A set of stash names which should be treated as garbage chutes.

- **completion_mode** – A function describing how multiple exploration techniques with the `complete` hook set will interact. By default, the builtin function `any`.

- **techniques** – A list of techniques that should be pre-set to use with this manager.

- **suggestions** – Whether to automatically install the Suggestions exploration technique. Default True.

**Variables:**

- **errored** – Not a stash, but a list of ErrorRecords. Whenever a step raises an exception that we catch, the state and some information about the error are placed in this list. You can adjust the list of caught exceptions with the resilience parameter.

- **stashes** – All the stashes on this instance, as a dictionary.

- **completion_mode** – A function describing how multiple exploration techniques with the `complete` hook set will interact. By default, the builtin function `any`.

#### `ALL: ALL = '_ALL'`

#### `DROP: DROP = '_DROP'`

#### `SimulationManager.__init__(project, active_states=None, stashes=None, hierarchy=None, resilience=None, save_unsat=False, auto_drop=None, errored=None, completion_mode=<built-in function any>, techniques=None, suggestions=True, **kwargs)`

#### `active: list[SimState]`

#### `stashed: list[SimState]`

#### `pruned: list[SimState]`

#### `unsat: list[SimState]`

#### `deadended: list[SimState]`

#### `unconstrained: list[SimState]`

#### `found: list[SimState]`

#### `one_active: SimState`

#### `one_stashed: SimState`

#### `one_pruned: SimState`

#### `one_unsat: SimState`

#### `one_deadended: SimState`

#### `one_unconstrained: SimState`

#### `one_found: SimState`

#### `errored: list[ErrorRecord]`

#### `stashes: defaultdict[str, list[SimState]]`

#### `SimulationManager.mulpyplex(*stashes)`

Mulpyplex across several stashes.

**Parameters:**

**stashes** – the stashes to mulpyplex

**Returns:**

a mulpyplexed list of states from the stashes in question, in the specified order

#### `SimulationManager.copy(deep=False)`

Make a copy of this simulation manager. Pass `deep=True` to copy all the states in it as well.

If the current callstack includes hooked methods, the already-called methods will not be included in the copy.

#### `SimulationManager.use_technique(tech)`

Use an exploration technique with this SimulationManager.

Techniques can be found in `angr.exploration_techniques`.

**Parameters:**

**tech** (*ExplorationTechnique*) – An ExplorationTechnique object that contains code to modify this SimulationManager’s behavior.

**Returns:**

The technique that was added, for convenience

#### `SimulationManager.remove_technique(tech)`

Remove an exploration technique from a list of active techniques.

**Parameters:**

**tech** (*ExplorationTechnique*) – An ExplorationTechnique object.

#### `SimulationManager.explore(stash='active', n=None, find=None, avoid=None, find_stash='found', avoid_stash='avoid', cfg=None, num_find=1, avoid_priority=False, **kwargs)`

Tick stash “stash” forward (up to “n” times or until “num_find” states are found), looking for condition “find”, avoiding condition “avoid”. Stores found states into “find_stash’ and avoided states into “avoid_stash”.

The “find” and “avoid” parameters may be any of:

- An address to find

- A set or list of addresses to find

- A function that takes a state and returns whether or not it matches.

If an angr CFG is passed in as the “cfg” parameter and “find” is either a number or a list or a set, then any states which cannot possibly reach a success state without going through a failure state will be preemptively avoided.

#### `SimulationManager.run(stash='active', n=None, until=None, **kwargs)`

Run until the SimulationManager has reached a completed state, according to the current exploration techniques. If no exploration techniques that define a completion state are being used, run until there is nothing left to run.

**Parameters:**

- **stash** – Operate on this stash

- **n** – Step at most this many times

- **until** – If provided, should be a function that takes a SimulationManager and returns True or False. Stepping will terminate when it is True.

**Returns:**

The simulation manager, for chaining.

**Return type:**

SimulationManager

#### `SimulationManager.complete()`

Returns whether or not this manager has reached a “completed” state.

#### `SimulationManager.step(stash='active', target_stash=None, n=None, selector_func=None, step_func=None, error_list=None, successor_func=None, until=None, filter_func=None, **run_args)`

Step a stash of states forward and categorize the successors appropriately.

The parameters to this function allow you to control everything about the stepping and categorization process.

**Parameters:**

- **stash** – The name of the stash to step (default: ‘active’)

- **target_stash** – The name of the stash to put the results in (default: same as `stash`)

- **error_list** – The list to put ErrorRecord objects in (default: `self.errored`)

- **selector_func** – If provided, should be a function that takes a state and returns a boolean. If True, the state will be stepped. Otherwise, it will be kept as-is.

- **step_func** – If provided, should be a function that takes a SimulationManager and returns a SimulationManager. Will be called with the SimulationManager at every step. Note that this function should not actually perform any stepping - it is meant to be a maintenance function called after each step.

- **successor_func** – If provided, should be a function that takes a state and return its successors. Otherwise, project.factory.successors will be used.

- **filter_func** – If provided, should be a function that takes a state and return the name of the stash, to which the state should be moved.

- **until** – (DEPRECATED) If provided, should be a function that takes a SimulationManager and returns True or False. Stepping will terminate when it is True.

- **n** – (DEPRECATED) The number of times to step (default: 1 if “until” is not provided)

Additionally, you can pass in any of the following keyword args for project.factory.successors:

**Parameters:**

- **jumpkind** – The jumpkind of the previous exit

- **addr** – An address to execute at instead of the state’s ip.

- **stmt_whitelist** – A list of stmt indexes to which to confine execution.

- **last_stmt** – A statement index at which to stop execution.

- **thumb** – Whether the block should be lifted in ARM’s THUMB mode.

- **backup_state** – A state to read bytes from instead of using project memory.

- **opt_level** – The VEX optimization level to use.

- **insn_bytes** – A string of bytes to use for the block instead of the project.

- **size** – The maximum size of the block, in bytes.

- **num_inst** – The maximum number of instructions.

- **traceflags** – traceflags to be passed to VEX. Default: 0

**Returns:**

The simulation manager, for chaining.

**Return type:**

SimulationManager

#### `SimulationManager.step_state(state, successor_func=None, error_list=None, **run_args)`

Don’t use this function manually - it is meant to interface with exploration techniques.

#### `SimulationManager.filter(state, filter_func=None)`

Don’t use this function manually - it is meant to interface with exploration techniques.

#### `SimulationManager.selector(state, selector_func=None)`

Don’t use this function manually - it is meant to interface with exploration techniques.

#### `SimulationManager.successors(state, successor_func=None, **run_args)`

Don’t use this function manually - it is meant to interface with exploration techniques.

#### `SimulationManager.prune(filter_func=None, from_stash='active', to_stash='pruned')`

Prune unsatisfiable states from a stash.

This function will move all unsatisfiable states in the given stash into a different stash.

**Parameters:**

- **filter_func** – Only prune states that match this filter.

- **from_stash** – Prune states from this stash. (default: ‘active’)

- **to_stash** – Put pruned states in this stash. (default: ‘pruned’)

**Returns:**

The simulation manager, for chaining.

**Return type:**

SimulationManager

#### `SimulationManager.populate(stash, states)`

Populate a stash with a collection of states.

**Parameters:**

- **stash** – A stash to populate.

- **states** – A list of states with which to populate the stash.

#### `SimulationManager.absorb(simgr)`

Collect all the states from `simgr` and put them in their corresponding stashes in this manager. This will not modify `simgr`.

#### `SimulationManager.move(from_stash, to_stash, filter_func=None)`

Move states from one stash to another.

**Parameters:**

- **from_stash** – Take matching states from this stash.

- **to_stash** – Put matching states into this stash.

- **filter_func** – Stash states that match this filter. Should be a function that takes a state and returns True or False. (default: stash all states)

**Returns:**

The simulation manager, for chaining.

**Return type:**

SimulationManager

#### `SimulationManager.stash(filter_func=None, from_stash='active', to_stash='stashed')`

Stash some states. This is an alias for move(), with defaults for the stashes.

**Parameters:**

- **filter_func** – Stash states that match this filter. Should be a function that takes a state and returns True or False. (default: stash all states)

- **from_stash** – Take matching states from this stash. (default: ‘active’)

- **to_stash** – Put matching states into this stash. (default: ‘stashed’)

**Returns:**

The simulation manager, for chaining.

**Return type:**

SimulationManager

#### `SimulationManager.unstash(filter_func=None, to_stash='active', from_stash='stashed')`

Unstash some states. This is an alias for move(), with defaults for the stashes.

**Parameters:**

- **filter_func** – Unstash states that match this filter. Should be a function that takes a state and returns True or False. (default: unstash all states)

- **from_stash** – take matching states from this stash. (default: ‘stashed’)

- **to_stash** – put matching states into this stash. (default: ‘active’)

**Returns:**

The simulation manager, for chaining.

**Return type:**

SimulationManager

#### `SimulationManager.drop(filter_func=None, stash='active')`

Drops states from a stash. This is an alias for move(), with defaults for the stashes.

**Parameters:**

- **filter_func** – Drop states that match this filter. Should be a function that takes a state and returns True or False. (default: drop all states)

- **stash** – Drop matching states from this stash. (default: ‘active’)

**Returns:**

The simulation manager, for chaining.

**Return type:**

SimulationManager

#### `SimulationManager.apply(state_func=None, stash_func=None, stash='active', to_stash=None)`

Applies a given function to a given stash.

**Parameters:**

- **state_func** – A function to apply to every state. Should take a state and return a state. The returned state will take the place of the old state. If the function *doesn’t* return a state, the old state will be used. If the function returns a list of states, they will replace the original states.

- **stash_func** – A function to apply to the whole stash. Should take a list of states and return a list of states. The resulting list will replace the stash. If both state_func and stash_func are provided state_func is applied first, then stash_func is applied on the results.

- **stash** – A stash to work with.

- **to_stash** – If specified, this stash will be used to store the resulting states instead.

**Returns:**

The simulation manager, for chaining.

**Return type:**

SimulationManager

#### `SimulationManager.split(stash_splitter=None, stash_ranker=None, state_ranker=None, limit=8, from_stash='active', to_stash='stashed')`

Split a stash of states into two stashes depending on the specified options.

The stash from_stash will be split into two stashes depending on the other options passed in. If to_stash is provided, the second stash will be written there.

stash_splitter overrides stash_ranker, which in turn overrides state_ranker. If no functions are provided, the states are simply split according to the limit.

The sort done with state_ranker is ascending.

**Parameters:**

- **stash_splitter** – A function that should take a list of states and return a tuple of two lists (the two resulting stashes).

- **stash_ranker** – A function that should take a list of states and return a sorted list of states. This list will then be split according to “limit”.

- **state_ranker** – An alternative to stash_splitter. States will be sorted with outputs of this function, which are to be used as a key. The first “limit” of them will be kept, the rest split off.

- **limit** – For use with state_ranker. The number of states to keep. Default: 8

- **from_stash** – The stash to split (default: ‘active’)

- **to_stash** – The stash to write to (default: ‘stashed’)

**Returns:**

The simulation manager, for chaining.

**Return type:**

SimulationManager

#### `SimulationManager.merge(merge_func=None, merge_key=None, stash='active', prune=True)`

Merge the states in a given stash.

**Parameters:**

- **stash** – The stash (default: ‘active’)

- **merge_func** – If provided, instead of using state.merge, call this function with the states as the argument. Should return the merged state.

- **merge_key** – If provided, should be a function that takes a state and returns a key that will compare equal for all states that are allowed to be merged together, as a first approximation. By default: uses PC, callstack, and open file descriptors.

- **prune** – Whether to prune the stash prior to merging it

**Returns:**

The simulation manager, for chaining.

**Return type:**

SimulationManager

### `ErrorRecord`

Bases: `object`

A container class for a state and an error that was thrown during its execution. You can find these in SimulationManager.errored.

**Variables:**

- **state** (`SimState`) – The state that encountered an error, at the point in time just before the erroring step began.

- **error** (`Exception`) – The error that was thrown.

- **traceback** (`TracebackType`) – The traceback for the error that was thrown.

#### `ErrorRecord.__init__(state, error, traceback)`

#### `state: SimState`

#### `error: Exception`

#### `traceback: TracebackType`

#### `ErrorRecord.debug()`

Launch a postmortem debug shell at the site of the error.

#### `ErrorRecord.reraise()`

---

## API 参考：angr.state_plugins.solver（SimSolver）

### `timed_function(f)`

### `enable_timing()`

### `disable_timing()`

### `error_converter(f)`

### `concrete_path_bool(f)`

### `concrete_path_not_bool(f)`

### `concrete_path_scalar(f)`

### `concrete_path_tuple(f)`

### `concrete_path_list(f)`

### `SimSolver`

Bases: `SimStatePlugin`

This is the plugin you’ll use to interact with symbolic variables, creating them and evaluating them. It should be available on a state as `state.solver`.

Any top-level variable of the claripy module can be accessed as a property of this object.

#### `SimSolver.__init__(solver=None, all_variables=None, temporal_tracked_variables=None, eternal_tracked_variables=None)`

#### `SimSolver.reload_solver(constraints=None)`

Reloads the solver. Useful when changing solver options.

**Parameters:**

**constraints** (*list*) – A new list of constraints to use in the reloaded solver instead of the current one

#### `SimSolver.get_variables(*keys)`

Iterate over all variables for which their tracking key is a prefix of the values provided.

Elements are a tuple, the first element is the full tracking key, the second is the symbol.

```
>>> list(s.solver.get_variables('mem'))
[(('mem', 0x1000), <BV64 mem_1000_4_64>), (('mem', 0x1008), <BV64 mem_1008_5_64>)]

```

```
>>> list(s.solver.get_variables('file'))
[(('file', 1, 0), <BV8 file_1_0_6_8>), (('file', 1, 1), <BV8 file_1_1_7_8>),
    (('file', 2, 0), <BV8 file_2_0_8_8>)]

```

```
>>> list(s.solver.get_variables('file', 2))
[(('file', 2, 0), <BV8 file_2_0_8_8>)]

```

```
>>> list(s.solver.get_variables())
[(('mem', 0x1000), <BV64 mem_1000_4_64>), (('mem', 0x1008), <BV64 mem_1008_5_64>),
    (('file', 1, 0), <BV8 file_1_0_6_8>), (('file', 1, 1), <BV8 file_1_1_7_8>),
    (('file', 2, 0), <BV8 file_2_0_8_8>)]

```

#### `SimSolver.register_variable(v, key, eternal=True)`

Register a value with the variable tracking system

**Parameters:**

- **v** – The BVS to register

- **key** – A tuple to register the variable under

**Parma eternal:**

Whether this is an eternal variable, default True. If False, an incrementing counter will be appended to the key.

#### `SimSolver.describe_variables(v)`

Given an AST, iterate over all the keys of all the BVS leaves in the tree which are registered.

#### `SimSolver.Unconstrained(name, bits, uninitialized=True, inspect=True, events=True, key=None, eternal=False, uc_alloc_depth=None, **kwargs)`

Creates an unconstrained symbol or a default concrete value (0), based on the state options.

**Parameters:**

- **name** – The name of the symbol.

- **bits** – The size (in bits) of the symbol.

- **uninitialized** – Whether this value should be counted as an “uninitialized” value in the course of an analysis.

- **inspect** – Set to False to avoid firing SimInspect breakpoints

- **events** – Set to False to avoid generating a SimEvent for the occasion

- **key** – Set this to a tuple of increasingly specific identifiers (for example, `('mem', 0xffbeff00)` or `('file', 4, 0x20)` to cause it to be tracked, i.e. accessible through `solver.get_variables`.

- **eternal** – Set to True in conjunction with setting a key to cause all states with the same ancestry to retrieve the same symbol when trying to create the value. If False, a counter will be appended to the key.

**Returns:**

an unconstrained symbol (or a concrete value of 0).

#### `SimSolver.BVS(name, size, min=None, max=None, stride=None, uninitialized=False, explicit_name=False, key=None, eternal=False, inspect=True, events=True, **kwargs)`

Creates a bit-vector symbol (i.e., a variable). Other keyword parameters are passed directly on to the constructor of claripy.ast.BV.

**Parameters:**

- **name** – The name of the symbol.

- **size** – The size (in bits) of the bit-vector.

- **min** – The minimum value of the symbol. Note that this **only** work when using VSA.

- **max** – The maximum value of the symbol. Note that this **only** work when using VSA.

- **stride** – The stride of the symbol. Note that this **only** work when using VSA.

- **uninitialized** – Whether this value should be counted as an “uninitialized” value in the course of an analysis.

- **explicit_name** – Set to True to prevent an identifier from appended to the name to ensure uniqueness.

- **key** – Set this to a tuple of increasingly specific identifiers (for example, `('mem', 0xffbeff00)` or `('file', 4, 0x20)` to cause it to be tracked, i.e. accessible through `solver.get_variables`.

- **eternal** – Set to True in conjunction with setting a key to cause all states with the same ancestry to retrieve the same symbol when trying to create the value. If False, a counter will be appended to the key.

- **inspect** – Set to False to avoid firing SimInspect breakpoints

- **events** – Set to False to avoid generating a SimEvent for the occasion

**Returns:**

A BV object representing this symbol.

#### `SimSolver.downsize()`

Frees memory associated with the constraint solver by clearing all of its internal caches.

#### `constraints`

Returns the constraints of the state stored by the solver.

#### `SimSolver.eval_to_ast(e, n, extra_constraints=(), exact=None)`

Evaluate an expression, using the solver if necessary. Returns AST objects.

**Parameters:**

- **e** – the expression

- **n** – the number of desired solutions

- **extra_constraints** – extra constraints to apply to the solver

- **exact** – if False, returns approximate solutions

**Returns:**

a tuple of the solutions, in the form of claripy AST nodes

**Return type:**

tuple

#### `SimSolver.max(e, extra_constraints=(), exact=None, signed=False)`

Return the maximum value of expression e.

:param e : expression (an AST) to evaluate :type extra_constraints: :param extra_constraints: extra constraints (as ASTs) to add to the solver for this solve :param exact : if False, return approximate solutions. :param signed : Whether the expression should be treated as a signed value. :return: the maximum possible value of e (backend object)

#### `SimSolver.min(e, extra_constraints=(), exact=None, signed=False)`

Return the minimum value of expression e.

:param e : expression (an AST) to evaluate :type extra_constraints: :param extra_constraints: extra constraints (as ASTs) to add to the solver for this solve :param exact : if False, return approximate solutions. :param signed : Whether the expression should be treated as a signed value. :return: the minimum possible value of e (backend object)

#### `SimSolver.solution(e, v, extra_constraints=(), exact=None)`

Return True if v is a solution of expr with the extra constraints, False otherwise.

**Parameters:**

- **e** – An expression (an AST) to evaluate

- **v** – The proposed solution (an AST)

- **extra_constraints** – Extra constraints (as ASTs) to add to the solver for this solve.

- **exact** – If False, return approximate solutions.

**Returns:**

True if v is a solution of expr, False otherwise

#### `SimSolver.is_true(e, extra_constraints=(), exact=None)`

If the expression provided is absolutely, definitely a true boolean, return True. Note that returning False doesn’t necessarily mean that the expression can be false, just that we couldn’t figure that out easily.

**Parameters:**

- **e** – An expression (an AST) to evaluate

- **extra_constraints** – Extra constraints (as ASTs) to add to the solver for this solve.

- **exact** – If False, return approximate solutions.

**Returns:**

True if v is definitely true, False otherwise

#### `SimSolver.is_false(e, extra_constraints=(), exact=None)`

If the expression provided is absolutely, definitely a false boolean, return True. Note that returning False doesn’t necessarily mean that the expression can be true, just that we couldn’t figure that out easily.

**Parameters:**

- **e** – An expression (an AST) to evaluate

- **extra_constraints** – Extra constraints (as ASTs) to add to the solver for this solve.

- **exact** – If False, return approximate solutions.

**Returns:**

True if v is definitely false, False otherwise

#### `SimSolver.unsat_core(extra_constraints=())`

This function returns the unsat core from the backend solver.

**Parameters:**

**extra_constraints** – Extra constraints (as ASTs) to add to the solver for this solve.

**Returns:**

The unsat core.

#### `SimSolver.satisfiable(extra_constraints=(), exact=None)`

This function does a constraint check and checks if the solver is in a sat state.

**Parameters:**

- **extra_constraints** – Extra constraints (as ASTs) to add to s for this solve

- **exact** – If False, return approximate solutions.

**Returns:**

True if sat, otherwise false

#### `SimSolver.add(*constraints)`

Add some constraints to the solver.

**Parameters:**

**constraints** – Pass any constraints that you want to add (ASTs) as varargs.

#### `CastType: CastType = ~CastType`

#### `SimSolver.eval_upto(e, n, cast_to=None, **kwargs)`

Evaluate an expression, using the solver if necessary. Returns primitives as specified by the cast_to parameter. Only certain primitives are supported, check the implementation of _cast_to to see which ones.

**Overloads:**

- **self**, **e** (claripy.ast.BV), **n** (int), **cast_to** (None), **kwargs** → list[int]

- **self**, **e** (claripy.ast.BV), **n** (int), **cast_to** (type[CastType]), **kwargs** → list[CastType]

- **self**, **e** (claripy.ast.Bool), **n** (int), **cast_to** (None), **kwargs** → list[bool]

- **self**, **e** (claripy.ast.Bool), **n** (int), **cast_to** (type[CastType]), **kwargs** → list[CastType]

- **self**, **e** (claripy.ast.FP), **n** (int), **cast_to** (None), **kwargs** → list[float]

- **self**, **e** (claripy.ast.FP), **n** (int), **cast_to** (type[CastType]), **kwargs** → list[CastType]

**Parameters:**

- **e** – the expression

- **n** – the number of desired solutions

- **extra_constraints** – extra constraints to apply to the solver

- **exact** – if False, returns approximate solutions

- **cast_to** – desired type of resulting values

**Returns:**

a tuple of the solutions, in the form of Python primitives

**Return type:**

tuple

#### `SimSolver.eval(e, cast_to=None, **kwargs)`

Evaluate an expression to get any possible solution. The desired output types can be specified using the cast_to parameter. extra_constraints can be used to specify additional constraints the returned values must satisfy.

**Overloads:**

- **self**, **e** (claripy.ast.BV), **cast_to** (None), **kwargs** → int

- **self**, **e** (claripy.ast.BV), **cast_to** (type[CastType]), **kwargs** → CastType

- **self**, **e** (claripy.ast.Bool), **cast_to** (None), **kwargs** → bool

- **self**, **e** (claripy.ast.Bool), **cast_to** (type[CastType]), **kwargs** → CastType

- **self**, **e** (claripy.ast.FP), **cast_to** (None), **kwargs** → float

- **self**, **e** (claripy.ast.FP), **cast_to** (type[CastType]), **kwargs** → CastType

**Parameters:**

- **e** – the expression to get a solution for

- **kwargs** – Any additional kwargs will be passed down to eval_upto

- **cast_to** – desired type of resulting values

**Raises:**

**SimUnsatError** – if no solution could be found satisfying the given constraints

**Returns:**

#### `SimSolver.eval_one(e, cast_to=None, **kwargs)`

Evaluate an expression to get the only possible solution. Errors if either no or more than one solution is returned. A kwarg parameter default can be specified to be returned instead of failure!

**Overloads:**

- **self**, **e** (claripy.ast.BV), **cast_to** (None), **kwargs** → int

- **self**, **e** (claripy.ast.BV), **cast_to** (type[CastType]), **kwargs** → CastType

- **self**, **e** (claripy.ast.Bool), **cast_to** (None), **kwargs** → bool

- **self**, **e** (claripy.ast.Bool), **cast_to** (type[CastType]), **kwargs** → CastType

- **self**, **e** (claripy.ast.FP), **cast_to** (None), **kwargs** → float

- **self**, **e** (claripy.ast.FP), **cast_to** (type[CastType]), **kwargs** → CastType

**Parameters:**

- **e** – the expression to get a solution for

- **cast_to** – desired type of resulting values

- **default** – A value can be passed as a kwarg here. It will be returned in case of failure.

- **kwargs** – Any additional kwargs will be passed down to eval_upto

**Raises:**

- **SimUnsatError** – if no solution could be found satisfying the given constraints

- **SimValueError** – if more than one solution was found to satisfy the given constraints

**Returns:**

The value for e

#### `SimSolver.eval_atmost(e, n, cast_to=None, **kwargs)`

Evaluate an expression to get at most n possible solutions. Errors if either none or more than n solutions are returned.

**Overloads:**

- **self**, **e** (claripy.ast.BV), **n** (int), **cast_to** (None), **kwargs** → list[int]

- **self**, **e** (claripy.ast.BV), **n** (int), **cast_to** (type[CastType]), **kwargs** → list[CastType]

- **self**, **e** (claripy.ast.Bool), **n** (int), **cast_to** (None), **kwargs** → list[bool]

- **self**, **e** (claripy.ast.Bool), **n** (int), **cast_to** (type[CastType]), **kwargs** → list[CastType]

- **self**, **e** (claripy.ast.FP), **n** (int), **cast_to** (None), **kwargs** → list[float]

- **self**, **e** (claripy.ast.FP), **n** (int), **cast_to** (type[CastType]), **kwargs** → list[CastType]

**Parameters:**

- **e** – the expression to get a solution for

- **n** – the inclusive upper limit on the number of solutions

- **cast_to** – desired type of resulting values

- **kwargs** – Any additional kwargs will be passed down to eval_upto

**Raises:**

- **SimUnsatError** – if no solution could be found satisfying the given constraints

- **SimValueError** – if more than n solutions were found to satisfy the given constraints

**Returns:**

The solutions for e

#### `SimSolver.eval_atleast(e, n, cast_to=None, **kwargs)`

Evaluate an expression to get at least n possible solutions. Errors if less than n solutions were found.

**Overloads:**

- **self**, **e** (claripy.ast.BV), **n** (int), **cast_to** (None), **kwargs** → list[int]

- **self**, **e** (claripy.ast.BV), **n** (int), **cast_to** (type[CastType]), **kwargs** → list[CastType]

- **self**, **e** (claripy.ast.Bool), **n** (int), **cast_to** (None), **kwargs** → list[bool]

- **self**, **e** (claripy.ast.Bool), **n** (int), **cast_to** (type[CastType]), **kwargs** → list[CastType]

- **self**, **e** (claripy.ast.FP), **n** (int), **cast_to** (None), **kwargs** → list[float]

- **self**, **e** (claripy.ast.FP), **n** (int), **cast_to** (type[CastType]), **kwargs** → list[CastType]

**Parameters:**

- **e** – the expression to get a solution for

- **n** – the inclusive lower limit on the number of solutions

- **cast_to** – desired type of resulting values

- **kwargs** – Any additional kwargs will be passed down to eval_upto

**Raises:**

- **SimUnsatError** – if no solution could be found satisfying the given constraints

- **SimValueError** – if less than n solutions were found to satisfy the given constraints

**Returns:**

The solutions for e

#### `SimSolver.eval_exact(e, n, cast_to=None, **kwargs)`

Evaluate an expression to get exactly the n possible solutions. Errors if any number of solutions other than n was found to exist.

**Overloads:**

- **self**, **e** (claripy.ast.BV), **n** (int), **cast_to** (None), **kwargs** → list[int]

- **self**, **e** (claripy.ast.BV), **n** (int), **cast_to** (type[CastType]), **kwargs** → list[CastType]

- **self**, **e** (claripy.ast.Bool), **n** (int), **cast_to** (None), **kwargs** → list[bool]

- **self**, **e** (claripy.ast.Bool), **n** (int), **cast_to** (type[CastType]), **kwargs** → list[CastType]

- **self**, **e** (claripy.ast.FP), **n** (int), **cast_to** (None), **kwargs** → list[float]

- **self**, **e** (claripy.ast.FP), **n** (int), **cast_to** (type[CastType]), **kwargs** → list[CastType]

**Parameters:**

- **e** – the expression to get a solution for

- **n** – the inclusive lower limit on the number of solutions

- **cast_to** – desired type of resulting values

- **kwargs** – Any additional kwargs will be passed down to eval_upto

**Raises:**

- **SimUnsatError** – if no solution could be found satisfying the given constraints

- **SimValueError** – if any number of solutions other than n were found to satisfy the given constraints

**Returns:**

The solutions for e

#### `SimSolver.min_int(e, extra_constraints=(), exact=None, signed=False)`

Return the minimum value of expression e.

:param e : expression (an AST) to evaluate :type extra_constraints: :param extra_constraints: extra constraints (as ASTs) to add to the solver for this solve :param exact : if False, return approximate solutions. :param signed : Whether the expression should be treated as a signed value. :return: the minimum possible value of e (backend object)

#### `SimSolver.max_int(e, extra_constraints=(), exact=None, signed=False)`

Return the maximum value of expression e.

:param e : expression (an AST) to evaluate :type extra_constraints: :param extra_constraints: extra constraints (as ASTs) to add to the solver for this solve :param exact : if False, return approximate solutions. :param signed : Whether the expression should be treated as a signed value. :return: the maximum possible value of e (backend object)

#### `SimSolver.unique(e, **kwargs)`

Returns True if the expression e has only one solution by querying the constraint solver. It does also add that unique solution to the solver’s constraints.

#### `SimSolver.symbolic(e)`

Returns True if the expression e is symbolic.

#### `SimSolver.single_valued(e)`

Returns True whether e is a concrete value or is a value set with only 1 possible value. This differs from unique in that this *does* not query the constraint solver.

#### `SimSolver.simplify(e=None)`

Simplifies e. If e is None, simplifies the constraints of this state.

#### `SimSolver.variables(e)`

Returns the symbolic variables present in the AST of e.

---

## API 参考：angr.state_plugins.light_registers

### `SimLightRegisters`

Bases: `SimStatePlugin`

#### `SimLightRegisters.__init__(reg_map=None, registers=None)`

#### `SimLightRegisters.resolve_register(offset, size)`

#### `SimLightRegisters.load(offset, size=None, **kwargs)`

#### `SimLightRegisters.store(offset, value, size=None, endness=None, **kwargs)`

---

## API 参考：angr.state_plugins.view

### `SimRegNameView`

Bases: `SimStatePlugin`

#### `SimRegNameView.get(reg_name)`

### `SimMemView`

Bases: `SimStatePlugin`

This is a convenient interface with which you can access a program’s memory.

The interface works like this:

> - You first use [array index notation] to specify the address you’d like to load from

- If at that address is a pointer, you may access the `deref` property to return a SimMemView at the address present in memory.

- You then specify a type for the data by simply accessing a property of that name. For a list of supported types, look at `state.mem.types`.

- You can then *refine* the type. Any type may support any refinement it likes. Right now the only refinements supported are that you may access any member of a struct by its member name, and you may index into a string or array to access that element.

- If the address you specified initially points to an array of that type, you can say .array(n) to view the data as an array of n elements.

- Finally, extract the structured data with `.resolved` or `.concrete`. `.resolved` will return bitvector values, while `.concrete` will return integer, string, array, etc values, whatever best represents the data.

- Alternately, you may store a value to memory, by assigning to the chain of properties that you’ve constructed. Note that because of the way python works, `x = s.mem[...].prop; x = val` will NOT work, you must say `s.mem[...].prop = val`.

For example:

```
>>> s.mem[0x601048].long
<long (64 bits) <BV64 0x4008d0> at 0x601048>
>>> s.mem[0x601048].long.resolved
<BV64 0x4008d0>
>>> s.mem[0x601048].deref
<<untyped> <unresolvable> at 0x4008d0>
>>> s.mem[0x601048].deref.string.concrete
'SOSNEAKY'

```

#### `SimMemView.__init__(ty=None, addr=None, state=None)`

#### `types: ClassVar[dict] = {'CharT': char, 'DIR': struct DIR, 'FILE': struct FILE, 'FILE_t': struct FILE_t, '_Bool': bool, '_ENTRY': struct _ENTRY, '_IO_codecvt': struct _IO_codecvt, '_IO_iconv_t': struct _IO_iconv_t, '_IO_lock_t': struct pthread_mutex_t, '_IO_marker': struct _IO_marker, '_IO_wide_data': struct _IO_wide_data, '__action_fn_t': __action_fn_t, '__clock_t': uint32_t, '__dev_t': uint64_t, '__free_fn_t': __free_fn_t, '__ftw_func_t': __ftw_func_t, '__gid_t': unsigned int, '__ino64_t': unsigned long long, '__ino_t': unsigned long, '__int128': int128_t, '__int256': int256_t, '__int32': int, '__int64': long long, '__mbstate_t': struct __mbstate_t, '__mode_t': unsigned int, '__nlink_t': unsigned int, '__off64_t': long long, '__off_t': long, '__pid_t': int, '__suseconds_t': int64_t, '__time_t': long, '__uid_t': unsigned int, '_obstack_chunk': struct _obstack_chunk, 'aiocb': struct aiocb, 'aiocb64': struct aiocb64, 'aioinit': struct aioinit, 'argp': struct argp, 'argp_child': struct argp_child, 'argp_option': struct argp_option, 'argp_parser_t': (int, char *, struct argp_state*) -> int, 'argp_state': struct argp_state, 'basic_string': string_t, 'bool': bool, 'byte': uint8_t, 'cc_t': char, 'char': char, 'clock_t': uint32_t, 'comparison_fn_t': comparison_fn_t, 'crypt_data': struct crypt_data, 'dev_t': int, 'dirent': struct dirent, 'dirent64': struct dirent64, 'double': double, 'drand48_data': struct <anon>, 'dword': uint32_t, 'error_t': int, 'exit_status': struct exit_status, 'fd_set': struct fd_set, 'float': float, 'fpos64_t': struct fpos64_t, 'fpos_t': struct fpos_t, 'fstab': struct fstab, 'glob64_t': struct glob64_t, 'glob_t': struct glob_t, 'group': struct group, 'hostent': struct hostent, 'hsearch_data': struct hsearch_data, 'if_nameindex': struct if_nameindex, 'in_addr': struct in_addr, 'in_port_t': uint16_t, 'ino64_t': unsigned long long, 'ino_t': unsigned long, 'int': int, 'int16_t': int16_t, 'int32_t': int32_t, 'int64_t': int64_t, 'int8_t': int8_t, 'iovec': struct <anon>, 'itimerval': struct itimerval, 'lconv': struct lconv, 'long': long, 'long double': double, 'long int': long, 'long long': long long, 'long long int': long long, 'long signed': long, 'long unsigned int': unsigned long, 'mallinfo': struct mallinfo, 'mallinfo2': struct mallinfo2, 'mbstate_t': struct mbstate_t, 'mntent': struct mntent, 'mode_t': unsigned int, 'netent': struct netent, 'ntptimeval': struct ntptimeval, 'obstack': struct obstack, 'off64_t': long long, 'off_t': long, 'option': struct option, 'passwd': struct passwd, 'pid_t': int, 'printf_info': struct printf_info, 'protoent': struct protoent, 'ptrdiff_t': long, 'qword': uint64_t, 'random_data': struct <anon>, 'regex_t': struct regex_t, 'rlim64_t': uint64_t, 'rlim_t': unsigned long, 'rlimit': struct rlimit, 'rlimit64': struct rlimit64, 'rusage': struct rusage, 'sa_family_t': unsigned short, 'sched_param': struct sched_param, 'sem_t': int, 'sembuf': struct sembuf, 'servent': struct servent, 'sgttyb': struct sgttyb, 'short': short, 'short int': short, 'sigevent': struct sigevent, 'sighandler_t': sighandler_t, 'signed': int, 'signed char': char, 'signed int': int, 'signed long': long, 'signed long int': long, 'signed long long': long long, 'signed long long int': long long, 'signed short': short, 'signed short int': short, 'sigset_t': int, 'sigstack': struct sigstack, 'sigval': union sigval { sival_int int; sival_ptr void *; }, 'size_t': size_t, 'sockaddr': struct sockaddr, 'sockaddr_in': struct sockaddr_in, 'socklen_t': uint32_t, 'speed_t': long, 'ssize': size_t, 'ssize_t': size_t, 'std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>': string_t, 'string': string_t, 'struct iovec': struct <anon>, 'struct stat': struct stat, 'struct stat64': struct stat64, 'struct timespec': struct timespec, 'struct timeval': struct timeval, 'tcflag_t': unsigned long, 'termios': struct termios, 'time_t': long, 'timespec': struct timeval, 'timeval': struct timeval, 'timex': struct timex, 'timezone': struct timezone, 'tm': struct tm, 'tms': struct tms, 'uint16_t': uint16_t, 'uint32_t': uint32_t, 'uint64_t': uint64_t, 'uint8_t': uint8_t, 'uintptr_t': unsigned long, 'unsigned': unsigned int, 'unsigned __int128': uint128_t, 'unsigned __int256': uint256_t, 'unsigned char': char, 'unsigned int': unsigned int, 'unsigned long': unsigned long, 'unsigned long int': unsigned long, 'unsigned long long': unsigned long long, 'unsigned long long int': unsigned long long, 'unsigned short': unsigned short, 'unsigned short int': unsigned short, 'utimbuf': struct utimbuf, 'utmp': struct utmp, 'utmpx': struct utmx, 'utsname': struct utsname, 'va_list': struct va_list[1], 'void': void, 'vtimes': struct vtimes, 'wchar_t': short, 'wctype_t': int, 'winsize': struct winsize, 'wint_t': int, 'word': uint16_t, 'wstring': wstring_t}`

#### `state: SimState[Any, Any] = None`

#### `struct: StructMode`

#### `SimMemView.with_type(sim_type)`

Returns a copy of the SimMemView with a type.

**Parameters:**

**sim_type** (`SimType`) – The new type.

**Return type:**

`SimMemView`

**Returns:**

The typed SimMemView copy.

#### `resolvable`

#### `resolved`

#### `concrete`

#### `deref: SimMemView`

#### `SimMemView.array(n)`

**Return type:**

`SimMemView`

#### `SimMemView.member(member_name)`

If self is a struct and member_name is a member of the struct, return that member element. Otherwise raise an exception.

**Return type:**

`SimMemView`

**Parameters:**

**member_name** (*str*)

#### `SimMemView.store(value)`

### `StructMode`

Bases: `object`

#### `StructMode.__init__(view)`

---

## API 参考：angr.storage

### `DefaultMemory`

Bases: `HexDumperMixin`, `SmartFindMixin`, `UnwrapperMixin`, `NameResolutionMixin`, `DataNormalizationMixin`, `SimplificationMixin`, `InspectMixin`, `ActionsMixinHigh`, `UnderconstrainedMixin`, `SizeConcretizationMixin`, `SizeNormalizationMixin`, `AddressConcretizationMixin`, `ActionsMixinLow`, `ConditionalMixin`, `ConvenientMappingsMixin`, `DirtyAddrsMixin`, `StackAllocationMixin`, `ClemoryBackerMixin`, `DictBackerMixin`, `PrivilegedPagingMixin`, `UltraPagesMixin`, `DefaultFillerMixin`, `SymbolicMergerMixin`, `PagedMemoryMixin`

### `SimFile`

Bases: `SimFileBase`, `DefaultMemory`

The normal SimFile is meant to model files on disk. It subclasses SimSymbolicMemory so loads and stores to/from it are very simple.

**Parameters:**

- **name** – The name of the file

- **content** – Optional initial content for the file as a string or bitvector

- **size** – Optional size of the file. If content is not specified, it defaults to zero

- **has_end** – Whether the size boundary is treated as the end of the file or a frontier at which new content will be generated. If unspecified, will pick its value based on options.FILES_HAVE_EOF. Another caveat is that if the size is also unspecified this value will default to False.

- **seekable** – Optional bool indicating whether seek operations on this file should succeed, default True.

- **writable** – Whether writing to this file is allowed

- **concrete** – Whether or not this file contains mostly concrete data. Will be used by some SimProcedures to choose how to handle variable-length operations like fgets.

**Variables:**

**has_end** – Whether this file has an EOF

#### `__init__(name=None, content=None, size=None, has_end=None, seekable=True, writable=True, ident=None, concrete=None, **kwargs)`

#### `category`

reg, mem, or file.

**Type:**

Return the category of this SimMemory instance. It can be one of the three following categories

#### `size`

The number of data bytes stored by the file at present. May be a symbolic value.

#### `concretize(**kwargs)`

Return a concretization of the contents of the file, as a flat bytestring.

### `SimMemoryObject`

Bases: `object`

A SimMemoryObject is a reference to a byte or several bytes in a specific object in memory. It should be used only by the bottom layer of memory.

#### `__init__(obj, base, endness, length=None, byte_width=8)`

#### `is_bytes`

#### `base`

#### `object: BV | FP`

#### `length`

#### `endness`

#### `size()`

#### `variables`

#### `symbolic`

#### `last_addr`

#### `concrete_bytes(offset, size)`

**Return type:**

`bytes` | `None`

**Parameters:**

- **offset** (*int*)

- **size** (*int*)

#### `includes(x)`

#### `bytes_at(addr, length, allow_concrete=False, endness='Iend_BE')`

Submodules

---

## API 参考：angr.storage.memory_mixins.memory_mixin

### `MemoryMixin`

Bases: `SimStatePlugin`, `Generic`

MemoryMixin is the base class for the memory model in angr. It provides a set of methods that should be implemented by memory models. This is done using mixins, where each mixin handles some specific feature of the memory model, only overriding methods that it needs to implement its function. The memory model class itself then combines a set of mixins using inheritence to form the final memory model class.

#### `SUPPORTS_CONCRETE_LOAD: bool = False`

#### `MemoryMixin.__init__(memory_id=None, endness='Iend_BE')`

**Parameters:**

- **memory_id** (*str** | **None*)

- **endness** (*str*)

#### `category: str`

reg, mem, or file.

**Type:**

Return the category of this SimMemory instance. It can be one of the three following categories

#### `variable_key_prefix: tuple[Any, ...]`

#### `MemoryMixin.find(addr, data, max_search, **kwargs)`

**Return type:**

`tuple`[`TypeVar`(`Addr`), `list`[`Bool`], `list`[`int`]]

**Parameters:**

- **addr** (*Addr*)

- **data** (*InData*)

- **max_search** (*int*)

#### `MemoryMixin.load(addr, size=None, **kwargs)`

**Return type:**

`TypeVar`(`OutData`)

**Parameters:**

- **addr** (*Addr*)

- **size** (*InData** | **None*)

#### `MemoryMixin.store(addr, data, size=None, **kwargs)`

**Return type:**

`None`

**Parameters:**

- **addr** (*Addr*)

- **data** (*InData*)

- **size** (*InData** | **None*)

#### `MemoryMixin.compare(other)`

**Return type:**

`bool`

**Parameters:**

**other** (*Self*)

#### `MemoryMixin.permissions(addr, permissions=None, **kwargs)`

**Return type:**

`BV`

**Parameters:**

- **addr** (*Addr*)

- **permissions** (*int** | **claripy.ast.BV** | **None*)

#### `MemoryMixin.map_region(addr, length, permissions, *, init_zero=False, **kwargs)`

**Parameters:**

- **addr** (*Addr*)

- **length** (*int*)

- **permissions** (*int** | **claripy.ast.BV*)

- **init_zero** (*bool*)

#### `MemoryMixin.unmap_region(addr, length, **kwargs)`

**Parameters:**

- **addr** (*Addr*)

- **length** (*int*)

#### `MemoryMixin.concrete_load(addr, size, writing=False, **kwargs)`

Set SUPPORTS_CONCRETE_LOAD to True and implement concrete_load if reading concrete bytes is faster in this memory model.

**Parameters:**

- **addr** – The address to load from.

- **size** – Size of the memory read.

- **writing**

**Return type:**

`Any`

**Returns:**

A memoryview into the loaded bytes.

#### `MemoryMixin.concrete_run_length(addr, size, **kwargs)`

Return the number of concrete bytes starting at `addr`, capped at `size`.

**Return type:**

`int`

#### `MemoryMixin.erase(addr, size=None, **kwargs)`

Set [addr:addr+size) to uninitialized. In many cases this will be faster than overwriting those locations with new values. This is commonly used during static data flow analysis.

**Parameters:**

- **addr** (`TypeVar`(`Addr`)) – The address to start erasing.

- **size** (`int` | `None`) – The number of bytes for erasing.

**Return type:**

`None`

**Returns:**

None

#### `MemoryMixin.replace_all(old, new)`

**Parameters:**

- **old** (*BV*)

- **new** (*BV*)

#### `MemoryMixin.copy_contents(dst, src, size, condition=None, **kwargs)`

Override this method to provide faster copying of large chunks of data.

**Parameters:**

- **dst** (`TypeVar`(`Addr`)) – The destination of copying.

- **src** (`TypeVar`(`Addr`)) – The source of copying.

- **size** (`TypeVar`(`InData`)) – The size of copying.

- **condition** (`Bool` | `None`) – The storing condition.

- **kwargs** – Other parameters.

**Returns:**

None

---

## API 参考：claripy 全量

Realistically, you should never have to work with in-depth claripy APIs unless you’re doing some hard-core analysis. Most of the time, you’ll be using claripy as a simple frontend to z3:

```
import claripy
a = claripy.BVS("sym_val", 32)
b = claripy.RotateLeft(a, 8)
c = b + 4
s = claripy.Solver()
s.add(c == 0x41424344)
assert s.eval(c, 1)[0] == 0x41424344
assert s.eval(a, 1)[0] == 0x40414243

```

Or using its components in angr:

```
import angr, claripy
b = angr.Project('/bin/true')
path = b.factory.path()
rax_start = claripy.BVS('rax_start', 64)
path.state.regs.rax = rax_start
path_new = path.step()[0]
rax_new = path_new.state.regs.rax
path_new.state.se.add(rax_new == 1337)
print(path_new.state.se.eval(rax_start, 1)[0])

```

## AST

### `BV`

Bases: `Bits`

A class representing an AST of operations culminating in a bitvector. Do not instantiate this class directly, instead use BVS or BVV to construct a symbol or value, and then use operations to construct more complicated expressions.

Individual sub-bits and bit-ranges can be extracted from a bitvector using index and slice notation. Bits are indexed weirdly. For a 32-bit AST:

> a[31] is the *LEFT* most bit, so it’d be the 0 in

> 01111111111111111111111111111111

a[0] is the *RIGHT* most bit, so it’d be the 0 in

> 11111111111111111111111111111110

a[31:30] are the two leftmost bits, so they’d be the 0s in:

> 00111111111111111111111111111111

a[1:0] are the two rightmost bits, so they’d be the 0s in:

> 11111111111111111111111111111100

**Parameters:**

- **op** (*str*)

- **args** (*Iterable**[**ArgType**]*)

- **add_variables** (*Iterable**[**str**] **| **None*)

- **hash** (*int** | **None*)

- **symbolic** (*bool** | **None*)

- **variables** (*frozenset**[**str**] **| **None*)

- **errored** (*set**[**Backend**] **| **None*)

- **annotations** (*tuple**[**Annotation**, **...**]*)

- **skip_child_annotations** (*bool*)

- **length** (*int** | **None*)

- **encoded_name** (*bytes** | **None*)

#### `BV.Concat(*args)`

#### `BV.Extract(*args)`

#### `BV.LShR()`

#### `BV.SDiv()`

#### `BV.SGE()`

#### `BV.SGT()`

#### `BV.SLE()`

#### `BV.SLT()`

#### `BV.SMod()`

#### `BV.UGE()`

#### `BV.UGT()`

#### `BV.ULE()`

#### `BV.ULT()`

#### `BV.chop(bits=1)`

Chops a BV into consecutive sub-slices. Obviously, the length of this BV must be a multiple of bits.

**Returns:**

A list of smaller bitvectors, each `bits` in length. The first one will be the left-most (i.e. most significant) bits.

#### `BV.concat(*args)`

Concatenates this bitvector with the bitvectors provided. This bitvector will be on the far-left, i.e. the most significant bits.

#### `BV.get_byte(index)`

Extracts a byte from a BV, where the index refers to the byte in a big-endian order

**Parameters:**

**index** – the byte to extract

**Returns:**

An 8-bit BV

#### `BV.get_bytes(index, size)`

Extracts several bytes from a bitvector, where the index refers to the byte in a big-endian order

**Parameters:**

- **index** – the byte index at which to start extracting

- **size** – the number of bytes to extract

**Returns:**

A BV of size `size * 8`

#### `BV.identical(other)`

Check if two ASTs are identical. If strict is False, the comparison will be lenient on the names of the ASTs.

**Return type:**

`bool`

**Parameters:**

**other** (*Self*)

#### `BV.intersection()`

#### `BV.raw_to_bv()`

A counterpart to FP.raw_to_bv - does nothing and returns itself.

#### `BV.raw_to_fp()`

Interpret the bits of this bitvector as an IEEE754 floating point number. The inverse of this function is raw_to_bv.

**Returns:**

An FP AST whose bit-pattern is the same as this BV

#### `reversed`

#### `BV.sign_extend(n)`

Sign-extends the bitvector by n bits. So:

> a = BVV(0b1111, 4) b = a.sign_extend(4) b is BVV(0b11111111)

#### `BV.to_bv()`

#### `BV.union()`

#### `BV.val_to_fp(sort, signed=True, rm=None)`

Interpret this bitvector as an integer, and return the floating-point representation of that integer.

**Parameters:**

- **sort** – The sort of floating point value to return

- **signed** – Optional: whether this value is a signed integer

- **rm** – Optional: the rounding mode to use

**Returns:**

An FP AST whose value is the same as this BV

#### `BV.widen()`

#### `BV.zero_extend(n)`

Zero-extends the bitvector by n bits. So:

> a = BVV(0b1111, 4) b = a.zero_extend(4) b is BVV(0b00001111)

### `FP`

Bases: `Bits`

An AST representing a set of operations culminating in an IEEE754 floating point number.

Do not instantiate this class directly, instead use FPV or FPS to construct a value or symbol, and then use operations to construct more complicated expressions.

**Variables:**

- **length** – The length of this value

- **sort** – The sort of this value, usually either FSORT_FLOAT or FSORT_DOUBLE

**Parameters:**

- **op** (*str*)

- **args** (*tuple**[**Base** | **bool** | **int** | **float** | **str** | **FSort** | **tuple**[**Base** | **bool** | **int** | **float** | **str** | **FSort** | **tuple**[**ArgType**] **| **None**] **| **None**, **...**]*)

- **add_variables** (*Iterable**[**str**] **| **None*)

- **hash** (*int** | **None*)

- **symbolic** (*bool*)

- **variables** (*frozenset**[**str**]*)

- **errored** (*set**[**Backend**] **| **None*)

- **annotations** (*tuple**[**Annotation**, **...**]*)

- **skip_child_annotations** (*bool*)

- **length** (*int** | **None*)

- **encoded_name** (*bytes** | **None*)

#### `FP.Sqrt()`

#### `FP.fpAbs()`

#### `FP.fpAdd()`

#### `FP.fpDiv()`

#### `FP.fpEQ()`

#### `FP.fpGEQ()`

#### `FP.fpGT()`

#### `FP.fpLEQ()`

#### `FP.fpLT()`

#### `FP.fpMul()`

#### `FP.fpNEQ()`

#### `FP.fpNeg()`

#### `FP.fpSqrt()`

#### `FP.fpSub()`

#### `FP.fpToFP()`

#### `FP.fpToFPUnsigned()`

#### `FP.fpToIEEEBV()`

#### `FP.isInf()`

#### `FP.isNaN()`

#### `FP.raw_to_bv()`

Interpret the bit-pattern of this IEEE754 floating point number as a bitvector. The inverse of this function is to_bv.

**Return type:**

`BV`

**Returns:**

A BV AST whose bit-pattern is the same as this FP

#### `FP.raw_to_fp()`

A counterpart to BV.raw_to_fp - does nothing and returns itself.

**Return type:**

`FP`

#### `sort: FSort`

#### `FP.to_bv()`

**Return type:**

`BV`

#### `FP.to_fp(sort, rm=None)`

Convert this float to a different sort

**Parameters:**

- **sort** – The sort to convert to

- **rm** – Optional: The rounding mode to use

**Return type:**

`FP`

**Returns:**

An FP AST

#### `FP.val_to_bv(size, signed=True, rm=None)`

Convert this floating point value to an integer.

**Parameters:**

- **size** – The size of the bitvector to return

- **signed** – Optional: Whether the target integer is signed

- **rm** – Optional: The rounding mode to use

**Return type:**

`BV`

**Returns:**

A bitvector whose value is the rounded version of this FP’s value

### `Base`

Bases: `object`

This is the base class of all claripy ASTs. An AST tracks a tree of operations on arguments.

This class should not be instanciated directly - instead, use one of the constructor functions (BVS, BVV, FPS, FPV…) to construct a leaf node and then build more complicated expressions using operations.

AST objects have *hash identity*. This means that an AST that has the same hash as another AST will be the *same* object. This is critical for efficient memory usage. As an example, the following is true:

```
a, b = two different ASTs
c = b + a
d = b + a
assert c is d

```

**Variables:**

- **op** – The operation that is being done on the arguments

- **args** – The arguments that are being used

**Parameters:**

- **op** (*str*)

- **args** (*tuple**[**Base** | **bool** | **int** | **float** | **str** | **FSort** | **tuple**[**Base** | **bool** | **int** | **float** | **str** | **FSort** | **tuple**[**ArgType**] **| **None**] **| **None**, **...**]*)

- **add_variables** (*Iterable**[**str**] **| **None*)

- **hash** (*int** | **None*)

- **symbolic** (*bool*)

- **variables** (*frozenset**[**str**]*)

- **errored** (*set**[**Backend**] **| **None*)

- **annotations** (*tuple**[**Annotation**, **...**]*)

- **skip_child_annotations** (*bool*)

- **length** (*int** | **None*)

- **encoded_name** (*bytes** | **None*)

#### `annotations: tuple[Annotation, ...]`

#### `args: tuple[Union[Base, bool, int, float, str, FSort, tuple[Union[Base, bool, int, float, str, FSort, tuple[ArgType], None]], None], ...]`

#### `depth: int`

#### `length: int | None`

#### `op: str`

#### `symbolic: bool`

#### `variables: frozenset[str]`

#### `Base.__init__(*args, **kwargs)`

#### `Base.annotate(*args, remove_annotations=None)`

Appends annotations to this AST.

**Parameters:**

- **args** (`Annotation`) – the tuple of annotations to append (variadic positional args)

- **remove_annotations** (`Iterable`[`Annotation`] | `None`) – annotations to remove

**Return type:**

`Self`

**Returns:**

a new AST, with the annotations added

#### `Base.append_annotation(a)`

Appends an annotation to this AST.

**Parameters:**

**a** (`Annotation`) – the annotation to append

**Return type:**

`Self`

**Returns:**

a new AST, with the annotation added

#### `Base.append_annotations(new_tuple)`

Appends several annotations to this AST.

**Parameters:**

**new_tuple** (`tuple`[`Annotation`, `...`]) – the tuple of annotations to append

**Return type:**

`Self`

**Returns:**

a new AST, with the annotations added

#### `Base.canonicalize(var_map=None, counter=None)`

**Return type:**

`tuple`[`dict`[`int`, `Base`], `int`, `Base`]

**Parameters:**

**counter** (*int** | **None*)

#### `cardinality: int`

#### `Base.children_asts()`

Return an iterator over the nested children ASTs.

**Return type:**

`Iterator`[`Base`]

#### `Base.clear_annotation_type(annotation_type)`

Removes all annotations of a given type from this AST.

**Parameters:**

**annotation_type** (`type`[`Annotation`]) – the type of annotations to remove

**Return type:**

`Self`

**Returns:**

a new AST, with the annotations removed

#### `Base.clear_annotations()`

Removes all annotations from this AST.

**Return type:**

`Self`

**Returns:**

a new AST, with all annotations removed

#### `concrete: bool`

#### `concrete_value`

#### `Base.dbg_is_looped()`

**Return type:**

`Base` | `bool`

#### `Base.dbg_repr(prefix=None)`

Returns a debug representation of this AST.

**Return type:**

`str`

#### `Base.get_annotation(annotation_type)`

Get the first annotation of a given type.

**Parameters:**

**annotation_type** (`type`[`TypeVar`(`A`, bound= Annotation)]) – The type of the annotation.

**Return type:**

`Optional`[`TypeVar`(`A`, bound= Annotation)]

**Returns:**

The annotation of the given type, or None if not found.

#### `Base.get_annotations_by_type(annotation_type)`

Get all annotations of a given type.

**Parameters:**

**annotation_type** (`type`[`TypeVar`(`A`, bound= Annotation)]) – The type of the annotation.

**Return type:**

`tuple`[`TypeVar`(`A`, bound= Annotation), `...`]

**Returns:**

A tuple of annotations of the given type.

#### `Base.has_annotation_type(annotation_type)`

Check if this AST has an annotation of a given type.

**Parameters:**

**annotation_type** (`type`[`Annotation`]) – The type of the annotation.

**Return type:**

`bool`

**Returns:**

True if the AST has an annotation of the given type.

#### `Base.hash()`

Python’s built in hash function is not collision resistant, so we use our own. When you call hash(ast), the value is derived from the claripy hash, but it gets passed through python’s non-resistent hash function first. This skips that step, allowing the claripy hash to be used directly, eg as a cache key.

**Return type:**

`int`

#### `Base.identical(other)`

Check if two ASTs are identical. If strict is False, the comparison will be lenient on the names of the ASTs.

**Return type:**

`bool`

**Parameters:**

**other** (*Self*)

#### `Base.insert_annotation(a)`

Inserts an annotation to this AST.

**Parameters:**

**a** (`Annotation`) – the annotation to insert

**Return type:**

`Self`

**Returns:**

a new AST, with the annotation added

#### `Base.insert_annotations(new_tuple)`

Inserts several annotations to this AST.

**Parameters:**

**new_tuple** (`tuple`[`Annotation`, `...`]) – the tuple of annotations to insert

**Return type:**

`Self`

**Returns:**

a new AST, with the annotations added

#### `Base.is_leaf()`

Check if this AST is a leaf node.

**Return type:**

`bool`

#### `Base.leaf_asts()`

Return an iterator over the leaf ASTs.

**Return type:**

`Iterator`[`Base`]

#### `Base.make_like(op, args, simplify=False, annotations=None, variables=None, symbolic=None, skip_child_annotations=False, length=None)`

**Return type:**

`Self`

**Parameters:**

- **op** (*str*)

- **args** (*Iterable**[**Base** | **bool** | **int** | **float** | **str** | **FSort** | **tuple**[**Base** | **bool** | **int** | **float** | **str** | **FSort** | **tuple**[**ArgType**] **| **None**] **| **None**]*)

- **simplify** (*bool*)

- **annotations** (*tuple**[**Annotation**, **...**] **| **None*)

- **variables** (*frozenset**[**str**] **| **None*)

- **symbolic** (*bool** | **None*)

- **skip_child_annotations** (*bool*)

- **length** (*int** | **None*)

#### `multivalued: bool`

#### `Base.remove_annotation(a)`

Removes an annotation from this AST.

**Parameters:**

**a** (`Annotation`) – the annotation to remove

**Return type:**

`Self`

**Returns:**

a new AST, with the annotation removed

#### `Base.remove_annotations(remove_sequence)`

Removes several annotations from this AST.

**Parameters:**

**remove_sequence** (`Iterable`[`Annotation`]) – a sequence/set of the annotations to remove

**Return type:**

`Self`

**Returns:**

a new AST, with the annotations removed

#### `Base.replace_annotations(new_tuple)`

Replaces annotations on this AST.

**Parameters:**

**new_tuple** (`tuple`[`Annotation`, `...`]) – the tuple of annotations to replace the old annotations with

**Return type:**

`Self`

**Returns:**

a new AST, with the annotations added

#### `Base.shallow_repr(max_depth=8, explicit_length=False, details=ReprLevel.LITE_REPR, inner=False, parent_prec=15, left=True)`

Returns a string representation of this AST, but with a maximum depth to prevent floods of text being printed.

**Parameters:**

- **max_depth** (`int`) – The maximum depth to print.

- **explicit_length** (`bool`) – Print lengths of BVV arguments.

- **details** (`ReprLevel`) – An integer value specifying how detailed the output should be: LITE_REPR - print short repr for both operations and BVs, MID_REPR - print full repr for operations and short for BVs, FULL_REPR - print full repr of both operations and BVs.

- **inner** (`bool`) – whether or not it is an inner AST

- **parent_prec** (`int`) – parent operation precedence level

- **left** (`bool`) – whether or not it is a left AST

**Return type:**

`str`

**Returns:**

A string representing the AST

#### `singlevalued: bool`

#### `Base.structurally_match(o)`

Structurally compares two A objects, and check if their corresponding leaves are definitely the same A object (name-wise or hash-identity wise).

**Parameters:**

**o** (`Base`) – the other claripy A object

**Return type:**

`bool`

**Returns:**

True/False

### `Bits`

Bases: `Base`

A base class for AST types that can be stored as a series of bits. Currently, this is bitvectors and IEEE floats.

**Variables:**

**length** – The length of this value in bits.

**Parameters:**

- **op** (*str*)

- **args** (*tuple**[**Base** | **bool** | **int** | **float** | **str** | **FSort** | **tuple**[**Base** | **bool** | **int** | **float** | **str** | **FSort** | **tuple**[**ArgType**] **| **None**] **| **None**, **...**]*)

- **add_variables** (*Iterable**[**str**] **| **None*)

- **hash** (*int** | **None*)

- **symbolic** (*bool*)

- **variables** (*frozenset**[**str**]*)

- **errored** (*set**[**Backend**] **| **None*)

- **annotations** (*tuple**[**Annotation**, **...**]*)

- **skip_child_annotations** (*bool*)

- **length** (*int** | **None*)

- **encoded_name** (*bytes** | **None*)

#### `Bits.make_like(op, args, **kwargs)`

#### `Bits.raw_to_bv()`

Converts this data’s bit-pattern to a bitvector.

#### `Bits.raw_to_fp()`

Converts this data’s bit-pattern to an IEEE float.

#### `Bits.size()`

**Return type:**

`int`

**Returns:**

The bit length of this AST

### `Bool`

Bases: `Base`

Bool is the AST class for a boolean value.

**Parameters:**

- **op** (*str*)

- **args** (*tuple**[**Base** | **bool** | **int** | **float** | **str** | **FSort** | **tuple**[**Base** | **bool** | **int** | **float** | **str** | **FSort** | **tuple**[**ArgType**] **| **None**] **| **None**, **...**]*)

- **add_variables** (*Iterable**[**str**] **| **None*)

- **hash** (*int** | **None*)

- **symbolic** (*bool*)

- **variables** (*frozenset**[**str**]*)

- **errored** (*set**[**Backend**] **| **None*)

- **annotations** (*tuple**[**Annotation**, **...**]*)

- **skip_child_annotations** (*bool*)

- **length** (*int** | **None*)

- **encoded_name** (*bytes** | **None*)

#### `Bool.intersection()`

#### `Bool.is_false()`

Returns True if ‘self’ can be easily determined to be False. Otherwise, return False. Note that the AST *might* still be False (i.e., if it were simplified via Z3), but it’s hard to quickly tell that.

#### `Bool.is_true()`

Returns True if ‘self’ can be easily determined to be True. Otherwise, return False. Note that the AST *might* still be True (i.e., if it were simplified via Z3), but it’s hard to quickly tell that.

#### `Bool.size()`

Returns the size of the AST in bits. A boolean is 1 bit.

### `String`

Bases: `Base`

Base class that represent the AST of a String object and implements all the operation useful to create and modify the AST.

Do not instantiate this class directly, instead use StringS or StringV to construct a symbol or value, and then use operations to construct more complicated expressions.

**Parameters:**

- **op** (*str*)

- **args** (*tuple**[**Base** | **bool** | **int** | **float** | **str** | **FSort** | **tuple**[**Base** | **bool** | **int** | **float** | **str** | **FSort** | **tuple**[**ArgType**] **| **None**] **| **None**, **...**]*)

- **add_variables** (*Iterable**[**str**] **| **None*)

- **hash** (*int** | **None*)

- **symbolic** (*bool*)

- **variables** (*frozenset**[**str**]*)

- **errored** (*set**[**Backend**] **| **None*)

- **annotations** (*tuple**[**Annotation**, **...**]*)

- **skip_child_annotations** (*bool*)

- **length** (*int** | **None*)

- **encoded_name** (*bytes** | **None*)

#### `String.IntToStr(*args)`

#### `String.StrConcat(*args)`

#### `String.StrContains(*args)`

#### `String.StrIndexOf(*args)`

#### `String.StrIsDigit(*args)`

#### `String.StrLen(*args)`

#### `String.StrPrefixOf(*args)`

#### `String.StrReplace(*args)`

#### `String.StrSubstr(*args)`

#### `String.StrSuffixOf(*args)`

#### `String.StrToInt(*args)`

#### `String.indexOf(pattern, start_idx)`

Return the start index of the pattern inside the input string in a Bitvector representation, otherwise it returns -1 (always using a BitVector)

#### `String.strReplace(str_to_replace, replacement)`

Replace the first occurence of str_to_replace with replacement

**Parameters:**

- **str_to_replace** (*claripy.ast.String*) – pattern that has to be replaced

- **replacement** (*claripy.ast.String*) – replacement pattern

#### `String.toInt()`

Convert the string to a bitvector holding the integer representation of the string

### `false()`

### `true()`

### `ReprLevel`

Bases: `IntEnum`

Representation levels for ASTs.

#### `LITE_REPR: LITE_REPR = 0`

#### `MID_REPR: MID_REPR = 1`

#### `FULL_REPR: FULL_REPR = 2`

### `Base`

Bases: `object`

This is the base class of all claripy ASTs. An AST tracks a tree of operations on arguments.

This class should not be instanciated directly - instead, use one of the constructor functions (BVS, BVV, FPS, FPV…) to construct a leaf node and then build more complicated expressions using operations.

AST objects have *hash identity*. This means that an AST that has the same hash as another AST will be the *same* object. This is critical for efficient memory usage. As an example, the following is true:

```
a, b = two different ASTs
c = b + a
d = b + a
assert c is d

```

**Variables:**

- **op** – The operation that is being done on the arguments

- **args** – The arguments that are being used

**Parameters:**

- **op** (*str*)

- **args** (*tuple**[**Base** | **bool** | **int** | **float** | **str** | **FSort** | **tuple**[**Base** | **bool** | **int** | **float** | **str** | **FSort** | **tuple**[**ArgType**] **| **None**] **| **None**, **...**]*)

- **add_variables** (*Iterable**[**str**] **| **None*)

- **hash** (*int** | **None*)

- **symbolic** (*bool*)

- **variables** (*frozenset**[**str**]*)

- **errored** (*set**[**Backend**] **| **None*)

- **annotations** (*tuple**[**Annotation**, **...**]*)

- **skip_child_annotations** (*bool*)

- **length** (*int** | **None*)

- **encoded_name** (*bytes** | **None*)

#### `op: str`

#### `args: tuple[Union[Base, bool, int, float, str, FSort, tuple[Union[Base, bool, int, float, str, FSort, tuple[ArgType], None]], None], ...]`

#### `length: int | None`

#### `variables: frozenset[str]`

#### `symbolic: bool`

#### `annotations: tuple[Annotation, ...]`

#### `depth: int`

#### `Base.make_like(op, args, simplify=False, annotations=None, variables=None, symbolic=None, skip_child_annotations=False, length=None)`

**Return type:**

`Self`

**Parameters:**

- **op** (*str*)

- **args** (*Iterable**[**Base** | **bool** | **int** | **float** | **str** | **FSort** | **tuple**[**Base** | **bool** | **int** | **float** | **str** | **FSort** | **tuple**[**ArgType**] **| **None**] **| **None**]*)

- **simplify** (*bool*)

- **annotations** (*tuple**[**Annotation**, **...**] **| **None*)

- **variables** (*frozenset**[**str**] **| **None*)

- **symbolic** (*bool** | **None*)

- **skip_child_annotations** (*bool*)

- **length** (*int** | **None*)

#### `Base.__init__(*args, **kwargs)`

#### `Base.hash()`

Python’s built in hash function is not collision resistant, so we use our own. When you call hash(ast), the value is derived from the claripy hash, but it gets passed through python’s non-resistent hash function first. This skips that step, allowing the claripy hash to be used directly, eg as a cache key.

**Return type:**

`int`

#### `Base.identical(other)`

Check if two ASTs are identical. If strict is False, the comparison will be lenient on the names of the ASTs.

**Return type:**

`bool`

**Parameters:**

**other** (*Self*)

#### `Base.has_annotation_type(annotation_type)`

Check if this AST has an annotation of a given type.

**Parameters:**

**annotation_type** (`type`[`Annotation`]) – The type of the annotation.

**Return type:**

`bool`

**Returns:**

True if the AST has an annotation of the given type.

#### `Base.get_annotations_by_type(annotation_type)`

Get all annotations of a given type.

**Parameters:**

**annotation_type** (`type`[`TypeVar`(`A`, bound= Annotation)]) – The type of the annotation.

**Return type:**

`tuple`[`TypeVar`(`A`, bound= Annotation), `...`]

**Returns:**

A tuple of annotations of the given type.

#### `Base.get_annotation(annotation_type)`

Get the first annotation of a given type.

**Parameters:**

**annotation_type** (`type`[`TypeVar`(`A`, bound= Annotation)]) – The type of the annotation.

**Return type:**

`Optional`[`TypeVar`(`A`, bound= Annotation)]

**Returns:**

The annotation of the given type, or None if not found.

#### `Base.append_annotation(a)`

Appends an annotation to this AST.

**Parameters:**

**a** (`Annotation`) – the annotation to append

**Return type:**

`Self`

**Returns:**

a new AST, with the annotation added

#### `Base.append_annotations(new_tuple)`

Appends several annotations to this AST.

**Parameters:**

**new_tuple** (`tuple`[`Annotation`, `...`]) – the tuple of annotations to append

**Return type:**

`Self`

**Returns:**

a new AST, with the annotations added

#### `Base.annotate(*args, remove_annotations=None)`

Appends annotations to this AST.

**Parameters:**

- **args** (`Annotation`) – the tuple of annotations to append (variadic positional args)

- **remove_annotations** (`Iterable`[`Annotation`] | `None`) – annotations to remove

**Return type:**

`Self`

**Returns:**

a new AST, with the annotations added

#### `Base.insert_annotation(a)`

Inserts an annotation to this AST.

**Parameters:**

**a** (`Annotation`) – the annotation to insert

**Return type:**

`Self`

**Returns:**

a new AST, with the annotation added

#### `Base.insert_annotations(new_tuple)`

Inserts several annotations to this AST.

**Parameters:**

**new_tuple** (`tuple`[`Annotation`, `...`]) – the tuple of annotations to insert

**Return type:**

`Self`

**Returns:**

a new AST, with the annotations added

#### `Base.replace_annotations(new_tuple)`

Replaces annotations on this AST.

**Parameters:**

**new_tuple** (`tuple`[`Annotation`, `...`]) – the tuple of annotations to replace the old annotations with

**Return type:**

`Self`

**Returns:**

a new AST, with the annotations added

#### `Base.remove_annotation(a)`

Removes an annotation from this AST.

**Parameters:**

**a** (`Annotation`) – the annotation to remove

**Return type:**

`Self`

**Returns:**

a new AST, with the annotation removed

#### `Base.remove_annotations(remove_sequence)`

Removes several annotations from this AST.

**Parameters:**

**remove_sequence** (`Iterable`[`Annotation`]) – a sequence/set of the annotations to remove

**Return type:**

`Self`

**Returns:**

a new AST, with the annotations removed

#### `Base.clear_annotations()`

Removes all annotations from this AST.

**Return type:**

`Self`

**Returns:**

a new AST, with all annotations removed

#### `Base.clear_annotation_type(annotation_type)`

Removes all annotations of a given type from this AST.

**Parameters:**

**annotation_type** (`type`[`Annotation`]) – the type of annotations to remove

**Return type:**

`Self`

**Returns:**

a new AST, with the annotations removed

#### `Base.dbg_repr(prefix=None)`

Returns a debug representation of this AST.

**Return type:**

`str`

#### `Base.shallow_repr(max_depth=8, explicit_length=False, details=ReprLevel.LITE_REPR, inner=False, parent_prec=15, left=True)`

Returns a string representation of this AST, but with a maximum depth to prevent floods of text being printed.

**Parameters:**

- **max_depth** (`int`) – The maximum depth to print.

- **explicit_length** (`bool`) – Print lengths of BVV arguments.

- **details** (`ReprLevel`) – An integer value specifying how detailed the output should be: LITE_REPR - print short repr for both operations and BVs, MID_REPR - print full repr for operations and short for BVs, FULL_REPR - print full repr of both operations and BVs.

- **inner** (`bool`) – whether or not it is an inner AST

- **parent_prec** (`int`) – parent operation precedence level

- **left** (`bool`) – whether or not it is a left AST

**Return type:**

`str`

**Returns:**

A string representing the AST

#### `Base.children_asts()`

Return an iterator over the nested children ASTs.

**Return type:**

`Iterator`[`Base`]

#### `Base.leaf_asts()`

Return an iterator over the leaf ASTs.

**Return type:**

`Iterator`[`Base`]

#### `Base.is_leaf()`

Check if this AST is a leaf node.

**Return type:**

`bool`

#### `Base.dbg_is_looped()`

**Return type:**

`Base` | `bool`

#### `Base.structurally_match(o)`

Structurally compares two A objects, and check if their corresponding leaves are definitely the same A object (name-wise or hash-identity wise).

**Parameters:**

**o** (`Base`) – the other claripy A object

**Return type:**

`bool`

**Returns:**

True/False

#### `Base.canonicalize(var_map=None, counter=None)`

**Return type:**

`tuple`[`dict`[`int`, `Base`], `int`, `Base`]

**Parameters:**

**counter** (*int** | **None*)

#### `concrete_value`

#### `singlevalued: bool`

#### `multivalued: bool`

#### `cardinality: int`

#### `concrete: bool`

### `Bits`

Bases: `Base`

A base class for AST types that can be stored as a series of bits. Currently, this is bitvectors and IEEE floats.

**Variables:**

**length** – The length of this value in bits.

**Parameters:**

- **op** (*str*)

- **args** (*tuple**[**Base** | **bool** | **int** | **float** | **str** | **FSort** | **tuple**[**Base** | **bool** | **int** | **float** | **str** | **FSort** | **tuple**[**ArgType**] **| **None**] **| **None**, **...**]*)

- **add_variables** (*Iterable**[**str**] **| **None*)

- **hash** (*int** | **None*)

- **symbolic** (*bool*)

- **variables** (*frozenset**[**str**]*)

- **errored** (*set**[**Backend**] **| **None*)

- **annotations** (*tuple**[**Annotation**, **...**]*)

- **skip_child_annotations** (*bool*)

- **length** (*int** | **None*)

- **encoded_name** (*bytes** | **None*)

#### `Bits.make_like(op, args, **kwargs)`

#### `Bits.size()`

**Return type:**

`int`

**Returns:**

The bit length of this AST

#### `Bits.raw_to_bv()`

Converts this data’s bit-pattern to a bitvector.

#### `Bits.raw_to_fp()`

Converts this data’s bit-pattern to an IEEE float.

### `Bool`

Bases: `Base`

Bool is the AST class for a boolean value.

**Parameters:**

- **op** (*str*)

- **args** (*tuple**[**Base** | **bool** | **int** | **float** | **str** | **FSort** | **tuple**[**Base** | **bool** | **int** | **float** | **str** | **FSort** | **tuple**[**ArgType**] **| **None**] **| **None**, **...**]*)

- **add_variables** (*Iterable**[**str**] **| **None*)

- **hash** (*int** | **None*)

- **symbolic** (*bool*)

- **variables** (*frozenset**[**str**]*)

- **errored** (*set**[**Backend**] **| **None*)

- **annotations** (*tuple**[**Annotation**, **...**]*)

- **skip_child_annotations** (*bool*)

- **length** (*int** | **None*)

- **encoded_name** (*bytes** | **None*)

#### `Bool.is_true()`

Returns True if ‘self’ can be easily determined to be True. Otherwise, return False. Note that the AST *might* still be True (i.e., if it were simplified via Z3), but it’s hard to quickly tell that.

#### `Bool.is_false()`

Returns True if ‘self’ can be easily determined to be False. Otherwise, return False. Note that the AST *might* still be False (i.e., if it were simplified via Z3), but it’s hard to quickly tell that.

#### `Bool.size()`

Returns the size of the AST in bits. A boolean is 1 bit.

#### `Bool.intersection()`

### `BoolS(name, explicit_name=None)`

Creates a boolean symbol (i.e., a variable).

**Parameters:**

- **name** – The name of the symbol

- **explicit_name** – If False, an identifier is appended to the name to ensure uniqueness.

**Return type:**

`Bool`

**Returns:**

A Bool object representing this symbol.

### `BoolV(val)`

**Return type:**

`Bool`

### `true()`

### `false()`

### `If(cond, true_value, false_value)`

### `ite_dict(i, d, default)`

Return an expression of if-then-else trees which expresses a switch tree :type i: :param i: The variable which may take on multiple values affecting the final result :type d: :param d: A dict mapping possible values for i to values which the result could be :type default: :param default: A default value that the expression should take on if i matches none of the keys of d :return: An expression encoding the result of the above

### `ite_cases(cases, default)`

Return an expression of if-then-else trees which expresses a series of alternatives

**Parameters:**

- **cases** – A list of tuples (c, v). c is the condition under which v should be the result of the expression

- **default** – A default value that the expression should take on if none of the c conditions are satisfied

**Returns:**

An expression encoding the result of the above

### `reverse_ite_cases(ast)`

Given an expression created by ite_cases, produce the cases that generated it :type ast: :param ast: :return:

### `constraint_to_si(expr)`

Convert a constraint to SI if possible.

**Parameters:**

**expr**

**Returns:**

### `BV`

Bases: `Bits`

A class representing an AST of operations culminating in a bitvector. Do not instantiate this class directly, instead use BVS or BVV to construct a symbol or value, and then use operations to construct more complicated expressions.

Individual sub-bits and bit-ranges can be extracted from a bitvector using index and slice notation. Bits are indexed weirdly. For a 32-bit AST:

> a[31] is the *LEFT* most bit, so it’d be the 0 in

> 01111111111111111111111111111111

a[0] is the *RIGHT* most bit, so it’d be the 0 in

> 11111111111111111111111111111110

a[31:30] are the two leftmost bits, so they’d be the 0s in:

> 00111111111111111111111111111111

a[1:0] are the two rightmost bits, so they’d be the 0s in:

> 11111111111111111111111111111100

**Parameters:**

- **op** (*str*)

- **args** (*tuple**[**Base** | **bool** | **int** | **float** | **str** | **FSort** | **tuple**[**Base** | **bool** | **int** | **float** | **str** | **FSort** | **tuple**[**ArgType**] **| **None**] **| **None**, **...**]*)

- **add_variables** (*Iterable**[**str**] **| **None*)

- **hash** (*int** | **None*)

- **symbolic** (*bool*)

- **variables** (*frozenset**[**str**]*)

- **errored** (*set**[**Backend**] **| **None*)

- **annotations** (*tuple**[**Annotation**, **...**]*)

- **skip_child_annotations** (*bool*)

- **length** (*int** | **None*)

- **encoded_name** (*bytes** | **None*)

#### `BV.chop(bits=1)`

Chops a BV into consecutive sub-slices. Obviously, the length of this BV must be a multiple of bits.

**Returns:**

A list of smaller bitvectors, each `bits` in length. The first one will be the left-most (i.e. most significant) bits.

#### `BV.get_byte(index)`

Extracts a byte from a BV, where the index refers to the byte in a big-endian order

**Parameters:**

**index** – the byte to extract

**Returns:**

An 8-bit BV

#### `BV.get_bytes(index, size)`

Extracts several bytes from a bitvector, where the index refers to the byte in a big-endian order

**Parameters:**

- **index** – the byte index at which to start extracting

- **size** – the number of bytes to extract

**Returns:**

A BV of size `size * 8`

#### `BV.zero_extend(n)`

Zero-extends the bitvector by n bits. So:

> a = BVV(0b1111, 4) b = a.zero_extend(4) b is BVV(0b00001111)

#### `BV.sign_extend(n)`

Sign-extends the bitvector by n bits. So:

> a = BVV(0b1111, 4) b = a.sign_extend(4) b is BVV(0b11111111)

#### `BV.concat(*args)`

Concatenates this bitvector with the bitvectors provided. This bitvector will be on the far-left, i.e. the most significant bits.

#### `BV.val_to_fp(sort, signed=True, rm=None)`

Interpret this bitvector as an integer, and return the floating-point representation of that integer.

**Parameters:**

- **sort** – The sort of floating point value to return

- **signed** – Optional: whether this value is a signed integer

- **rm** – Optional: the rounding mode to use

**Returns:**

An FP AST whose value is the same as this BV

#### `BV.raw_to_fp()`

Interpret the bits of this bitvector as an IEEE754 floating point number. The inverse of this function is raw_to_bv.

**Returns:**

An FP AST whose bit-pattern is the same as this BV

#### `BV.raw_to_bv()`

A counterpart to FP.raw_to_bv - does nothing and returns itself.

#### `BV.to_bv()`

#### `BV.identical(other)`

Check if two ASTs are identical. If strict is False, the comparison will be lenient on the names of the ASTs.

**Return type:**

`bool`

**Parameters:**

**other** (*Self*)

#### `BV.Concat(*args)`

#### `BV.Extract(*args)`

#### `BV.LShR()`

#### `BV.SDiv()`

#### `BV.SGE()`

#### `BV.SGT()`

#### `BV.SLE()`

#### `BV.SLT()`

#### `BV.SMod()`

#### `BV.UGE()`

#### `BV.UGT()`

#### `BV.ULE()`

#### `BV.ULT()`

#### `BV.intersection()`

#### `reversed`

#### `BV.union()`

#### `BV.widen()`

### `BVS(name, size, explicit_name=None, **kwargs)`

Creates a bit-vector symbol (i.e., a variable).

If you want to specify the maximum or minimum value of a normal symbol that is not part of value-set analysis, you should manually add constraints to that effect. **Do not use ``min`` and ``max`` for symbolic execution.**

**Parameters:**

- **name** – The name of the symbol.

- **size** – The size (in bits) of the bit-vector.

- **explicit_name** (*bool*) – If False, an identifier is appended to the name to ensure uniqueness.

**Return type:**

`BV`

**Returns:**

a BV object representing this symbol.

### `BVV(value, size=None, **kwargs)`

Creates a bit-vector value (i.e., a concrete value).

**Parameters:**

- **value** – The value. Either an integer or a bytestring. If it’s the latter, it will be interpreted as the bytes of a big-endian constant.

- **size** – The size (in bits) of the bit-vector. Optional if you provide a string, required for an integer.

**Return type:**

`BV`

**Returns:**

A BV object representing this value.

### `SI(name='unnamed', bits=0, lower_bound=None, upper_bound=None, stride=None, explicit_name=None)`

### `TSI(bits, name=None, explicit_name=None)`

### `ESI(bits, **kwargs)`

### `ValueSet(bits, region, region_base_addr, value)`

**Parameters:**

- **bits** (*int*)

- **region** (*str*)

- **region_base_addr** (*int*)

- **value** (*BV** | **int*)

### `VS(bits, region, region_base_addr, value)`

**Parameters:**

- **bits** (*int*)

- **region** (*str*)

- **region_base_addr** (*int*)

- **value** (*BV** | **int*)

### `FP`

Bases: `Bits`

An AST representing a set of operations culminating in an IEEE754 floating point number.

Do not instantiate this class directly, instead use FPV or FPS to construct a value or symbol, and then use operations to construct more complicated expressions.

**Variables:**

- **length** – The length of this value

- **sort** – The sort of this value, usually either FSORT_FLOAT or FSORT_DOUBLE

**Parameters:**

- **op** (*str*)

- **args** (*tuple**[**Base** | **bool** | **int** | **float** | **str** | **FSort** | **tuple**[**Base** | **bool** | **int** | **float** | **str** | **FSort** | **tuple**[**ArgType**] **| **None**] **| **None**, **...**]*)

- **add_variables** (*Iterable**[**str**] **| **None*)

- **hash** (*int** | **None*)

- **symbolic** (*bool*)

- **variables** (*frozenset**[**str**]*)

- **errored** (*set**[**Backend**] **| **None*)

- **annotations** (*tuple**[**Annotation**, **...**]*)

- **skip_child_annotations** (*bool*)

- **length** (*int** | **None*)

- **encoded_name** (*bytes** | **None*)

#### `FP.to_fp(sort, rm=None)`

Convert this float to a different sort

**Parameters:**

- **sort** – The sort to convert to

- **rm** – Optional: The rounding mode to use

**Return type:**

`FP`

**Returns:**

An FP AST

#### `FP.raw_to_fp()`

A counterpart to BV.raw_to_fp - does nothing and returns itself.

**Return type:**

`FP`

#### `FP.raw_to_bv()`

Interpret the bit-pattern of this IEEE754 floating point number as a bitvector. The inverse of this function is to_bv.

**Return type:**

`BV`

**Returns:**

A BV AST whose bit-pattern is the same as this FP

#### `FP.to_bv()`

**Return type:**

`BV`

#### `FP.val_to_bv(size, signed=True, rm=None)`

Convert this floating point value to an integer.

**Parameters:**

- **size** – The size of the bitvector to return

- **signed** – Optional: Whether the target integer is signed

- **rm** – Optional: The rounding mode to use

**Return type:**

`BV`

**Returns:**

A bitvector whose value is the rounded version of this FP’s value

#### `sort: FSort`

#### `FP.Sqrt()`

#### `FP.fpAbs()`

#### `FP.fpAdd()`

#### `FP.fpDiv()`

#### `FP.fpEQ()`

#### `FP.fpGEQ()`

#### `FP.fpGT()`

#### `FP.fpLEQ()`

#### `FP.fpLT()`

#### `FP.fpMul()`

#### `FP.fpNEQ()`

#### `FP.fpNeg()`

#### `FP.fpSqrt()`

#### `FP.fpSub()`

#### `FP.fpToFP()`

#### `FP.fpToFPUnsigned()`

#### `FP.fpToIEEEBV()`

#### `FP.isInf()`

#### `FP.isNaN()`

### `FPS(name, sort, explicit_name=None)`

Creates a floating-point symbol.

**Parameters:**

- **name** – The name of the symbol

- **sort** – The sort of the floating point

- **explicit_name** – If False, an identifier is appended to the name to ensure uniqueness.

**Return type:**

`FP`

**Returns:**

An FP AST.

### `FPV(value, sort)`

Creates a concrete floating-point value.

**Parameters:**

- **value** – The value of the floating point.

- **sort** – The sort of the floating point.

**Return type:**

`FP`

**Returns:**

An FP AST.

### `String`

Bases: `Base`

Base class that represent the AST of a String object and implements all the operation useful to create and modify the AST.

Do not instantiate this class directly, instead use StringS or StringV to construct a symbol or value, and then use operations to construct more complicated expressions.

**Parameters:**

- **op** (*str*)

- **args** (*tuple**[**Base** | **bool** | **int** | **float** | **str** | **FSort** | **tuple**[**Base** | **bool** | **int** | **float** | **str** | **FSort** | **tuple**[**ArgType**] **| **None**] **| **None**, **...**]*)

- **add_variables** (*Iterable**[**str**] **| **None*)

- **hash** (*int** | **None*)

- **symbolic** (*bool*)

- **variables** (*frozenset**[**str**]*)

- **errored** (*set**[**Backend**] **| **None*)

- **annotations** (*tuple**[**Annotation**, **...**]*)

- **skip_child_annotations** (*bool*)

- **length** (*int** | **None*)

- **encoded_name** (*bytes** | **None*)

#### `String.strReplace(str_to_replace, replacement)`

Replace the first occurence of str_to_replace with replacement

**Parameters:**

- **str_to_replace** (*claripy.ast.String*) – pattern that has to be replaced

- **replacement** (*claripy.ast.String*) – replacement pattern

#### `String.toInt()`

Convert the string to a bitvector holding the integer representation of the string

#### `String.indexOf(pattern, start_idx)`

Return the start index of the pattern inside the input string in a Bitvector representation, otherwise it returns -1 (always using a BitVector)

#### `String.IntToStr(*args)`

#### `String.StrConcat(*args)`

#### `String.StrContains(*args)`

#### `String.StrIndexOf(*args)`

#### `String.StrIsDigit(*args)`

#### `String.StrLen(*args)`

#### `String.StrPrefixOf(*args)`

#### `String.StrReplace(*args)`

#### `String.StrSubstr(*args)`

#### `String.StrSuffixOf(*args)`

#### `String.StrToInt(*args)`

### `StringS(name, explicit_name=False, **kwargs)`

Create a new symbolic string (analogous to z3.String())

**Parameters:**

- **name** – The name of the symbolic string (i. e. the name of the variable)

- **explicit_name** (*bool*) – If False, an identifier is appended to the name to ensure uniqueness.

**Returns:**

The String object representing the symbolic string

### `StringV(value, **kwargs)`

Create a new Concrete string (analogous to z3.StringVal())

**Parameters:**

**value** – The constant value of the concrete string

**Returns:**

The String object representing the concrete string

## Backends

### `Backend`

Bases: `object`

Backends are Claripy’s workhorses. Claripy exposes ASTs (claripy.ast.Base objects) to the world, but when actual computation has to be done, it pushes those ASTs into objects that can be handled by the backends themselves. This provides a unified interface to the outside world while allowing Claripy to support different types of computation. For example, BackendConcrete provides computation support for concrete bitvectors and booleans, BackendVSA introduces VSA constructs such as StridedIntervals (and details what happens when operations are performed on them), and BackendZ3 provides support for symbolic variables and constraint solving.

There are a set of functions that a backend is expected to implement. For all of these functions, the “public” version is expected to be able to deal with claripy.ast.Base objects, while the “private” version should only deal with objects specific to the backend itself. This is distinguished with Python idioms: a public function will be named func() while a private function will be _func(). All functions should return objects that are usable by the backend in its private methods. If this can’t be done (i.e., some functionality is being attempted that the backend can’t handle), the backend should raise a BackendError. In this case, Claripy will move on to the next backend in its list.

All backends must implement a convert() function. This function receives a claripy.ast.Base and should return an object that the backend can handle in its private methods. Backends should also implement a _convert() method, which will receive anything that is *not* a claripy.ast.Base object (i.e., an integer or an object from a different backend). If convert() or _convert() receives something that the backend can’t translate to a format that is usable internally, the backend should raise BackendError, and thus won’t be used for that object.

Claripy contract with its backends is as follows: backends should be able to can handle, in their private functions, any object that they return from their private *or* public functions. Likewise, Claripy will never pass an object to any backend private function that did not originate as a return value from a private or public function of that backend. One exception to this is _convert(), as Claripy can try to stuff anything it feels like into _convert() to see if the backend can handle that type of object.

#### `Backend.__init__(solver_required=None)`

#### `Backend.add(s, c, track=False)`

This function adds constraints to the backend solver.

**Parameters:**

- **c** – A sequence of ASTs

- **s** – A backend solver object

- **track** (*bool*) – True to enable constraint tracking, which is used in unsat_core()

#### `Backend.apply_annotation(o, a)`

This should apply the annotation on the backend object, and return a new backend object.

**Parameters:**

- **o** – A backend object.

- **a** – An Annotation object.

**Returns:**

A backend object.

#### `Backend.batch_eval(exprs, n, extra_constraints=(), solver=None, model_callback=None)`

Evaluate one or multiple expressions.

**Parameters:**

- **exprs** – A list of expressions to evaluate.

- **n** – Number of different solutions to return.

- **extra_constraints** – Extra constraints (as ASTs) to add to the solver for this solve.

- **solver** – A solver object, native to the backend, to assist in the evaluation.

- **model_callback** – a function that will be executed with recovered models (if any)

**Returns:**

A list of up to n tuples, where each tuple is a solution for all expressions.

#### `Backend.call(op, args)`

Calls operation op on args args with this backend.

**Returns:**

A backend object representing the result.

#### `Backend.cardinality(a)`

This should return the maximum number of values that an expression can take on. This should be a strict *over* approximation.

**Parameters:**

**a** – The AST to evaluate

**Returns:**

An integer

#### `Backend.check_satisfiability(extra_constraints=(), solver=None, model_callback=None)`

This function does a constraint check and returns the solvers state

**Parameters:**

- **solver** – The backend solver object.

- **extra_constraints** – Extra constraints (as ASTs) to add to s for this solve

- **model_callback** – a function that will be executed with recovered models (if any)

**Returns:**

‘SAT’, ‘UNSAT’, or ‘UNKNOWN’

#### `Backend.convert(expr)`

Resolves a claripy.ast.Base into something usable by the backend.

**Parameters:**

- **expr** – The expression.

- **save** – Save the result in the expression’s object cache

**Returns:**

A backend object.

#### `Backend.convert_list(args)`

#### `Backend.default_op(expr)`

#### `Backend.downsize()`

Clears all caches associated with this backend.

#### `Backend.eval(expr, n, extra_constraints=(), solver=None, model_callback=None)`

This function returns up to n possible solutions for expression expr.

**Parameters:**

- **expr** – expression (an AST) to evaluate

- **n** – number of results to return

- **solver** – a solver object, native to the backend, to assist in the evaluation (for example, a z3.Solver)

- **extra_constraints** – extra constraints (as ASTs) to add to the solver for this solve

- **model_callback** – a function that will be executed with recovered models (if any)

**Returns:**

A sequence of up to n results (backend objects)

#### `Backend.handles(expr)`

Checks whether this backend can handle the expression.

**Parameters:**

**expr** – The expression.

**Returns:**

True if the backend can handle this expression, False if not.

#### `Backend.has_false(e, extra_constraints=(), solver=None, model_callback=None)`

Should return False if e can possibly be False.

**Parameters:**

- **e** – The AST.

- **extra_constraints** – Extra constraints (as ASTs) to add to the solver for this solve.

- **solver** – A solver, for backends that require it.

- **model_callback** – a function that will be executed with recovered models (if any)

**Returns:**

A boolean.

#### `Backend.has_true(e, extra_constraints=(), solver=None, model_callback=None)`

Should return True if e can possible be True.

**Parameters:**

- **e** – The AST.

- **extra_constraints** – Extra constraints (as ASTs) to add to the solver for this solve.

- **solver** – A solver, for backends that require it.

- **model_callback** – a function that will be executed with recovered models (if any)

**Returns:**

A boolean

#### `Backend.identical(a, b)`

This should return whether a is identical to b. Of course, this isn’t always clear. True should mean that it is definitely identical. False eans that, conservatively, it might not be.

**Parameters:**

- **a** – an AST

- **b** – another AST

**Return type:**

`bool`

#### `Backend.is_false(e, extra_constraints=(), solver=None, model_callback=None)`

Should return True if e can be easily found to be False.

**Parameters:**

- **e** – The AST

- **extra_constraints** – Extra constraints (as ASTs) to add to the solver for this solve.

- **solver** – A solver, for backends that require it

- **model_callback** – a function that will be executed with recovered models (if any)

**Returns:**

A boolean.

#### `Backend.is_true(e, extra_constraints=(), solver=None, model_callback=None)`

Should return True if e can be easily found to be True.

**Parameters:**

- **e** – The AST.

- **extra_constraints** – Extra constraints (as ASTs) to add to the solver for this solve.

- **solver** – A solver, for backends that require it.

- **model_callback** – a function that will be executed with recovered models (if any)

**Returns:**

A boolean.

#### `Backend.max(expr, extra_constraints=(), signed=False, solver=None, model_callback=None)`

Return the maximum value of expr.

**Parameters:**

- **expr** – expression (an AST) to evaluate

- **solver** – a solver object, native to the backend, to assist in the evaluation (for example, a z3.Solver)

- **extra_constraints** – extra constraints (as ASTs) to add to the solver for this solve

- **signed** – Whether to solve for the maximum signed integer instead of the unsigned max

- **model_callback** – a function that will be executed with recovered models (if any)

**Returns:**

the maximum possible value of expr (backend object)

#### `Backend.min(expr, extra_constraints=(), signed=False, solver=None, model_callback=None)`

Return the minimum value of expr.

**Parameters:**

- **expr** – expression (an AST) to evaluate

- **solver** – a solver object, native to the backend, to assist in the evaluation (for example, a z3.Solver)

- **extra_constraints** – extra constraints (as ASTs) to add to the solver for this solve

- **signed** – Whether to solve for the minimum signed integer instead of the unsigned min

- **model_callback** – a function that will be executed with recovered models (if any)

**Returns:**

the minimum possible value of expr (backend object)

#### `Backend.multivalued(a)`

#### `Backend.name(a)`

This should return the name of an expression.

**Parameters:**

**a** – the AST to evaluate

#### `Backend.satisfiable(extra_constraints=(), solver=None, model_callback=None)`

This function does a constraint check and checks if the solver is in a sat state.

**Parameters:**

- **solver** – The backend solver object.

- **extra_constraints** – Extra constraints (as ASTs) to add to s for this solve

- **model_callback** – a function that will be executed with recovered models (if any)

**Returns:**

True if sat, otherwise false

#### `Backend.simplify(expr)`

#### `Backend.singlevalued(a)`

#### `Backend.solution(expr, v, extra_constraints=(), solver=None, model_callback=None)`

Return True if v is a solution of expr with the extra constraints, False otherwise.

**Parameters:**

- **expr** – An expression (an AST) to evaluate

- **v** – The proposed solution (an AST)

- **solver** – A solver object, native to the backend, to assist in the evaluation (for example, a z3.Solver).

- **extra_constraints** – Extra constraints (as ASTs) to add to the solver for this solve.

- **model_callback** – a function that will be executed with recovered models (if any)

**Returns:**

True if v is a solution of expr, False otherwise

#### `Backend.solver(timeout=None)`

This function should return an instance of whatever object handles solving for this backend. For example, in Z3, this would be z3.Solver().

#### `Backend.unsat_core(s)`

This function returns the unsat core from the backend solver.

**Parameters:**

**s** – A backend solver object.

**Returns:**

The unsat core.

### `BackendConcrete`

Bases: `Backend`

#### `BackendConcrete.BVV(value, size)`

#### `BackendConcrete.FPV(op, sort)`

#### `BackendConcrete.StringV(value)`

#### `BackendConcrete.__init__()`

#### `BackendConcrete.convert(expr)`

Override Backend.convert() to add fast paths for BVVs and BoolVs.

#### `BackendConcrete.is_false(e, extra_constraints=(), solver=None, model_callback=None)`

Should return True if e can be easily found to be False.

**Parameters:**

- **e** – The AST

- **extra_constraints** – Extra constraints (as ASTs) to add to the solver for this solve.

- **solver** – A solver, for backends that require it

- **model_callback** – a function that will be executed with recovered models (if any)

**Returns:**

A boolean.

#### `BackendConcrete.is_true(e, extra_constraints=(), solver=None, model_callback=None)`

Should return True if e can be easily found to be True.

**Parameters:**

- **e** – The AST.

- **extra_constraints** – Extra constraints (as ASTs) to add to the solver for this solve.

- **solver** – A solver, for backends that require it.

- **model_callback** – a function that will be executed with recovered models (if any)

**Returns:**

A boolean.

### `BackendVSA`

Bases: `Backend`

BackendVSA is a backend that uses VSA (Value Set Analysis) to represent and reason about values.

#### `BackendVSA.And(a, *args)`

#### `BackendVSA.BVS(ast)`

**Parameters:**

**ast** (*BV*)

#### `BackendVSA.BVV(ast)`

#### `BackendVSA.BoolV(ast)`

#### `BackendVSA.Concat(*args)`

#### `BackendVSA.CreateTopStridedInterval(bits, name=None)`

#### `BackendVSA.Extract(*args)`

#### `BackendVSA.If(cond, t, f)`

#### `BackendVSA.LShR(expr, shift_amount)`

#### `BackendVSA.Not(a)`

#### `BackendVSA.Or(*args)`

#### `BackendVSA.Reverse(arg)`

#### `BackendVSA.SGE(a, b)`

#### `BackendVSA.SGT(a, b)`

#### `BackendVSA.SLE(a, b)`

#### `BackendVSA.SLT(a, b)`

#### `BackendVSA.SignExt(*args)`

#### `BackendVSA.UGE(a, b)`

#### `BackendVSA.UGT(a, b)`

#### `BackendVSA.ULE(a, b)`

#### `BackendVSA.ULT(a, b)`

#### `BackendVSA.ZeroExt(*args)`

#### `BackendVSA.__init__()`

#### `BackendVSA.apply_annotation(o, a)`

Apply an annotation on the backend object.

**Parameters:**

- **bo** (*BackendObject*) – The backend object.

- **annotation** (*Annotation*) – The annotation to be applied

**Returns:**

A new BackendObject

**Return type:**

BackendObject

#### `BackendVSA.constraint_to_si(expr)`

#### `BackendVSA.convert(expr)`

Resolves a claripy.ast.Base into something usable by the backend.

**Parameters:**

- **expr** – The expression.

- **save** – Save the result in the expression’s object cache

**Returns:**

A backend object.

#### `BackendVSA.intersection(ast)`

#### `BackendVSA.name(a)`

This should return the name of an expression.

**Parameters:**

**a** – the AST to evaluate

#### `BackendVSA.union(ast)`

#### `BackendVSA.widen(ast)`

### `BackendZ3`

Bases: `Backend`

#### `BackendZ3.BVS(**kwargs)`

The Z3 condom intercepts Z3Exceptions and throws a ClaripyZ3Error instead.

#### `BackendZ3.BVV(**kwargs)`

The Z3 condom intercepts Z3Exceptions and throws a ClaripyZ3Error instead.

#### `BackendZ3.BoolS(**kwargs)`

The Z3 condom intercepts Z3Exceptions and throws a ClaripyZ3Error instead.

#### `BackendZ3.BoolV(**kwargs)`

The Z3 condom intercepts Z3Exceptions and throws a ClaripyZ3Error instead.

#### `BackendZ3.FPS(**kwargs)`

The Z3 condom intercepts Z3Exceptions and throws a ClaripyZ3Error instead.

#### `BackendZ3.FPV(**kwargs)`

The Z3 condom intercepts Z3Exceptions and throws a ClaripyZ3Error instead.

#### `BackendZ3.StringS(**kwargs)`

The Z3 condom intercepts Z3Exceptions and throws a ClaripyZ3Error instead.

#### `BackendZ3.StringV(**kwargs)`

The Z3 condom intercepts Z3Exceptions and throws a ClaripyZ3Error instead.

#### `BackendZ3.__init__(reuse_z3_solver=None, ast_cache_size=10000)`

#### `BackendZ3.add(s, c, track=False)`

This function adds constraints to the backend solver.

**Parameters:**

- **c** – A sequence of ASTs

- **s** – A backend solver object

- **track** (*bool*) – True to enable constraint tracking, which is used in unsat_core()

#### `bvs_annotations: dict[bytes, tuple[Annotation, ...]]`

#### `BackendZ3.call(*args, **kwargs)`

Calls operation op on args args with this backend.

**Returns:**

A backend object representing the result.

#### `BackendZ3.clone_solver(s)`

#### `BackendZ3.downsize()`

Clears all caches associated with this backend.

#### `BackendZ3.simplify(**kwargs)`

The Z3 condom intercepts Z3Exceptions and throws a ClaripyZ3Error instead.

#### `BackendZ3.solver(timeout=None, max_memory=None)`

This function should return an instance of whatever object handles solving for this backend. For example, in Z3, this would be z3.Solver().

### `BVV`

Bases: `object`

A concrete bitvector value. Used in the concrete backend for calculations. Any use outside of claripy should use claripy.BVV instead.

#### `bits`

#### `mod`

#### `BVV.UGE(o)`

#### `BVV.UGT(o)`

#### `BVV.ULE(o)`

#### `BVV.ULT(o)`

#### `BVV.__init__(value, bits)`

#### `signed`

#### `BVV.size()`

#### `value`

### `FPV`

Bases: `object`

A concrete floating point value. Used in the concrete backend for calculations. Any use outside of claripy should use claripy.FPV instead.

#### `sort`

#### `value`

#### `FPV.__init__(value, sort)`

#### `FPV.fpSqrt()`

### `BackendConcrete`

Bases: `Backend`

#### `BackendConcrete.BVV(value, size)`

#### `BackendConcrete.FPV(op, sort)`

#### `BackendConcrete.StringV(value)`

#### `BackendConcrete.__init__()`

#### `BackendConcrete.convert(expr)`

Override Backend.convert() to add fast paths for BVVs and BoolVs.

#### `BackendConcrete.is_false(e, extra_constraints=(), solver=None, model_callback=None)`

Should return True if e can be easily found to be False.

**Parameters:**

- **e** – The AST

- **extra_constraints** – Extra constraints (as ASTs) to add to the solver for this solve.

- **solver** – A solver, for backends that require it

- **model_callback** – a function that will be executed with recovered models (if any)

**Returns:**

A boolean.

#### `BackendConcrete.is_true(e, extra_constraints=(), solver=None, model_callback=None)`

Should return True if e can be easily found to be True.

**Parameters:**

- **e** – The AST.

- **extra_constraints** – Extra constraints (as ASTs) to add to the solver for this solve.

- **solver** – A solver, for backends that require it.

- **model_callback** – a function that will be executed with recovered models (if any)

**Returns:**

A boolean.

### `StringV`

Bases: `object`

A concrete string value. Used in the concrete backend for calculations. Any use outside of claripy should use claripy.StringV instead.

#### `StringV.__init__(value)`

### `SigintHandler`

Bases: `object`

#### `SigintHandler.__init__(prev)`

### `install_sigint_handler()`

**Return type:**

`bool`

### `uninstall_sigint_handler()`

### `z3_expr_to_smt2(f, status='unknown', name='benchmark', logic='')`

### `claripy_solver_to_smt2(s)`

### `int_to_str_unlimited(v)`

Convert an integer to a decimal string, without any size limit.

**Parameters:**

**v** (`int`) – The integer to convert.

**Return type:**

`str`

**Returns:**

The string.

### `Z3_to_int_str(val)`

### `str_to_int_unlimited(s)`

Convert a decimal string to an integer, without any size limit.

**Parameters:**

**s** (`str`) – The string to convert.

**Return type:**

`int`

**Returns:**

The integer.

### `condom(f)`

### `z3_solver_sat(solver, extra_constraints, occasion)`

### `SmartLRUCache`

Bases: `LRUCache`

#### `SmartLRUCache.__init__(maxsize, getsizeof=None, evict=None)`

#### `SmartLRUCache.popitem()`

Remove and return the (key, value) pair least recently used.

### `BackendZ3`

Bases: `Backend`

#### `BackendZ3.__init__(reuse_z3_solver=None, ast_cache_size=10000)`

#### `bvs_annotations: dict[bytes, tuple[Annotation, ...]]`

#### `BackendZ3.downsize()`

Clears all caches associated with this backend.

#### `BackendZ3.BVS(**kwargs)`

The Z3 condom intercepts Z3Exceptions and throws a ClaripyZ3Error instead.

#### `BackendZ3.BVV(**kwargs)`

The Z3 condom intercepts Z3Exceptions and throws a ClaripyZ3Error instead.

#### `BackendZ3.FPS(**kwargs)`

The Z3 condom intercepts Z3Exceptions and throws a ClaripyZ3Error instead.

#### `BackendZ3.FPV(**kwargs)`

The Z3 condom intercepts Z3Exceptions and throws a ClaripyZ3Error instead.

#### `BackendZ3.BoolS(**kwargs)`

The Z3 condom intercepts Z3Exceptions and throws a ClaripyZ3Error instead.

#### `BackendZ3.BoolV(**kwargs)`

The Z3 condom intercepts Z3Exceptions and throws a ClaripyZ3Error instead.

#### `BackendZ3.StringV(**kwargs)`

The Z3 condom intercepts Z3Exceptions and throws a ClaripyZ3Error instead.

#### `BackendZ3.StringS(**kwargs)`

The Z3 condom intercepts Z3Exceptions and throws a ClaripyZ3Error instead.

#### `BackendZ3.call(*args, **kwargs)`

Calls operation op on args args with this backend.

**Returns:**

A backend object representing the result.

#### `BackendZ3.solver(timeout=None, max_memory=None)`

This function should return an instance of whatever object handles solving for this backend. For example, in Z3, this would be z3.Solver().

#### `BackendZ3.clone_solver(s)`

#### `BackendZ3.add(s, c, track=False)`

This function adds constraints to the backend solver.

**Parameters:**

- **c** – A sequence of ASTs

- **s** – A backend solver object

- **track** (*bool*) – True to enable constraint tracking, which is used in unsat_core()

#### `BackendZ3.simplify(**kwargs)`

The Z3 condom intercepts Z3Exceptions and throws a ClaripyZ3Error instead.

### `BackendVSA`

Bases: `Backend`

BackendVSA is a backend that uses VSA (Value Set Analysis) to represent and reason about values.

#### `BackendVSA.And(a, *args)`

#### `BackendVSA.BVS(ast)`

**Parameters:**

**ast** (*BV*)

#### `BackendVSA.BVV(ast)`

#### `BackendVSA.BoolV(ast)`

#### `BackendVSA.Concat(*args)`

#### `BackendVSA.CreateTopStridedInterval(bits, name=None)`

#### `BackendVSA.Extract(*args)`

#### `BackendVSA.If(cond, t, f)`

#### `BackendVSA.LShR(expr, shift_amount)`

#### `BackendVSA.Not(a)`

#### `BackendVSA.Or(*args)`

#### `BackendVSA.Reverse(arg)`

#### `BackendVSA.SGE(a, b)`

#### `BackendVSA.SGT(a, b)`

#### `BackendVSA.SLE(a, b)`

#### `BackendVSA.SLT(a, b)`

#### `BackendVSA.SignExt(*args)`

#### `BackendVSA.UGE(a, b)`

#### `BackendVSA.UGT(a, b)`

#### `BackendVSA.ULE(a, b)`

#### `BackendVSA.ULT(a, b)`

#### `BackendVSA.ZeroExt(*args)`

#### `BackendVSA.__init__()`

#### `BackendVSA.apply_annotation(o, a)`

Apply an annotation on the backend object.

**Parameters:**

- **bo** (*BackendObject*) – The backend object.

- **annotation** (*Annotation*) – The annotation to be applied

**Returns:**

A new BackendObject

**Return type:**

BackendObject

#### `BackendVSA.constraint_to_si(expr)`

#### `BackendVSA.convert(expr)`

Resolves a claripy.ast.Base into something usable by the backend.

**Parameters:**

- **expr** – The expression.

- **save** – Save the result in the expression’s object cache

**Returns:**

A backend object.

#### `BackendVSA.intersection(ast)`

#### `BackendVSA.name(a)`

This should return the name of an expression.

**Parameters:**

**a** – the AST to evaluate

#### `BackendVSA.union(ast)`

#### `BackendVSA.widen(ast)`

### `Balancer`

Bases: `object`

The Balancer is an equation redistributor. The idea is to take an AST and rebalance it to, for example, isolate unknown terms on one side of an inequality.

#### `Balancer.__init__(c)`

#### `comparison_info: comparison_info = {'SGE': (False, True, False), 'SGT': (False, False, False), 'SLE': (True, True, False), 'SLT': (True, False, False), 'UGE': (False, True, True), 'UGT': (False, False, True), 'ULE': (True, True, True), 'ULT': (True, False, True)}`

#### `compat_ret`

#### `replacements`

### `BoolResult`

Bases: `object`

A class representing the result of a boolean operation. Values can be True, False, or Maybe.

**Parameters:**

**value** (*tuple**[**bool**, **...**]*)

#### `BoolResult.__init__(value)`

**Parameters:**

**value** (*tuple**[**bool**, **...**]*)

#### `cardinality`

#### `BoolResult.has_false(o)`

#### `BoolResult.has_true(o)`

#### `BoolResult.identical(other)`

#### `BoolResult.is_false(o)`

#### `BoolResult.is_maybe(o)`

#### `BoolResult.is_true(o)`

#### `BoolResult.union(other)`

#### `value: tuple[bool, ...]`

### `DiscreteStridedIntervalSet`

Bases: `StridedInterval`

A DiscreteStridedIntervalSet represents one or more discrete StridedInterval instances.

#### `DiscreteStridedIntervalSet.UGE(o)`

Operation >=

**Parameters:**

**o** – The other operand.

**Returns:**

An instance of BoolResult.

#### `DiscreteStridedIntervalSet.UGT(o)`

Operation >

**Parameters:**

**o** – The other operand.

**Returns:**

An instance of BoolResult.

#### `DiscreteStridedIntervalSet.ULE(o)`

Operation <=

**Parameters:**

**o** – The other operand.

**Returns:**

An instance of BoolResult.

#### `DiscreteStridedIntervalSet.ULT(o)`

Operation <

**Parameters:**

**o** – The other operand.

**Returns:**

An instance of BoolResult.

#### `DiscreteStridedIntervalSet.__init__(name=None, bits=0, si_set=None, max_cardinality=None)`

#### `cardinality`

This is an over-approximation of the cardinality of this DSIS.

**Returns:**

#### `DiscreteStridedIntervalSet.collapse()`

Collapse into a StridedInterval instance.

**Returns:**

A new StridedInterval instance.

#### `DiscreteStridedIntervalSet.concat(b)`

Operation concat

**Parameters:**

**b** – The other operand to concatenate with.

**Returns:**

The concatenated value.

#### `DiscreteStridedIntervalSet.copy()`

#### `DiscreteStridedIntervalSet.eval(n, signed=False)`

**Parameters:**

- **n**

- **signed**

**Returns:**

#### `DiscreteStridedIntervalSet.extract(high_bit, low_bit)`

Operation extract

**Parameters:**

- **high_bit** – The highest bit to begin extraction.

- **low_bit** – The lowest bit to end extraction.

**Returns:**

Extracted bits.

#### `DiscreteStridedIntervalSet.intersection(b)`

#### `DiscreteStridedIntervalSet.normalize()`

Return the collapsed object if `should_collapse()` is True, otherwise return self.

**Returns:**

A DiscreteStridedIntervalSet object.

#### `number_of_values`

#### `DiscreteStridedIntervalSet.reverse()`

Operation Reverse

**Returns:**

None

#### `DiscreteStridedIntervalSet.should_collapse()`

#### `DiscreteStridedIntervalSet.sign_extend(new_length)`

Operation SignExt

**Parameters:**

**new_length** – The length to extend to.

**Returns:**

SignExtended value.

#### `stride`

#### `DiscreteStridedIntervalSet.union(b)`

The union operation. It might return a DiscreteStridedIntervalSet to allow for better precision in analysis.

**Parameters:**

**b** – Operand

**Returns:**

A new DiscreteStridedIntervalSet, or a new StridedInterval.

#### `DiscreteStridedIntervalSet.widen(b)`

Widening operator.

**Parameters:**

**b** – The other operand.

**Returns:**

The widened result.

#### `DiscreteStridedIntervalSet.zero_extend(new_length)`

Operation ZeroExt

**Parameters:**

**new_length** – The length to extend to.

**Returns:**

ZeroExtended value.

### `FalseResult()`

Return a BoolResult representing the value False.

**Return type:**

`BoolResult`

### `MaybeResult()`

Return a BoolResult representing the value Maybe.

**Return type:**

`BoolResult`

### `StridedInterval`

Bases: `object`

A Strided Interval is represented in the following form:

```
<bits> stride[lower_bound, upper_bound]

```

For more details, please refer to relevant papers like TIE and WYSINWYE.

This implementation is signedness-agostic, please refer to [1] *Signedness-Agnostic Program Analysis: Precise Integer Bounds for Low-Level Code* by Jorge A. Navas, etc. for more details.

Note that this implementation only takes hint from [1]. Such a work has been improved to be more precise (and still sound) when dealing with strided intervals. DO NOT expect to see a 1-to-1 reproduction of [1].

Thanks all corresponding authors for their outstanding works.

**Parameters:**

- **name** (*str** | **None*)

- **bits** (*int*)

- **stride** (*int*)

- **lower_bound** (*int** | **None*)

- **upper_bound** (*int** | **None*)

- **uninitialized** (*bool*)

- **bottom** (*bool*)

- **reversed** (*bool*)

#### `StridedInterval.LShR(shift_amount)`

Logical shift right. :param StridedInterval shift_amount: The amount of shifting :return: The shifted StridedInterval object :rtype: StridedInterval

**Parameters:**

**shift_amount** (*StridedInterval*)

**Return type:**

*StridedInterval*

#### `StridedInterval.SGE(o)`

Signed greater than or equal to.

**Parameters:**

**o** (`StridedInterval`) – The other operand

**Return type:**

`BoolResult`

**Returns:**

TrueResult(), FalseResult(), or MaybeResult()

#### `StridedInterval.SGT(o)`

Signed greater than.

**Parameters:**

**o** (`StridedInterval`) – The other operand

**Return type:**

`BoolResult`

**Returns:**

TrueResult(), FalseResult(), or MaybeResult()

#### `StridedInterval.SLE(o)`

Signed less than or equal to.

**Parameters:**

**o** (`StridedInterval`) – The other operand.

**Return type:**

`BoolResult`

**Returns:**

TrueResult(), FalseResult(), or MaybeResult()

#### `StridedInterval.SLT(o)`

Signed less than

**Parameters:**

**o** (`StridedInterval`) – The other operand

**Return type:**

`BoolResult`

**Returns:**

TrueResult(), FalseResult(), or MaybeResult()

#### `StridedInterval.UGE(o)`

Unsigned greater than or equal to.

**Parameters:**

**o** (`StridedInterval`) – The other operand

**Return type:**

`BoolResult`

**Returns:**

TrueResult(), FalseResult(), or MaybeResult()

#### `StridedInterval.UGT(o)`

Signed greater than.

**Parameters:**

**o** (`StridedInterval`) – The other operand

**Return type:**

`BoolResult`

**Returns:**

TrueResult(), FalseResult(), or MaybeResult()

#### `StridedInterval.ULE(o)`

Unsigned less than or equal to.

**Parameters:**

**o** (`StridedInterval`) – The other operand

**Return type:**

`BoolResult`

**Returns:**

TrueResult(), FalseResult(), or MaybeResult()

#### `StridedInterval.ULT(o)`

Unsigned less than.

**Parameters:**

**o** (`StridedInterval`) – The other operand

**Return type:**

`BoolResult`

**Returns:**

TrueResult(), FalseResult(), or MaybeResult()

#### `StridedInterval.__init__(name=None, bits=0, stride=1, lower_bound=None, upper_bound=None, uninitialized=False, bottom=False, reversed=False)`

**Parameters:**

- **name** (*str** | **None*)

- **bits** (*int*)

- **stride** (*int*)

- **lower_bound** (*int** | **None*)

- **upper_bound** (*int** | **None*)

- **uninitialized** (*bool*)

- **bottom** (*bool*)

- **reversed** (*bool*)

#### `StridedInterval.add(b)`

Binary operation: add

**Parameters:**

**b** (`StridedInterval`) – The other operand

**Return type:**

`StridedInterval`

**Returns:**

self + b

#### `StridedInterval.agnostic_extend(*args, **kwargs)`

#### `bits`

#### `StridedInterval.bitwise_and(t)`

Binary operation: logical and

**Parameters:**

- **b** – The other operand

- **t** (*StridedInterval*)

**Return type:**

`StridedInterval`

**Returns:**

The following code implements the and operations as presented in the paper ‘Signedness-Agnostic Program Analysis: Precise Integer Bounds for Low-Level Code’

#### `StridedInterval.bitwise_not(*args, **kwargs)`

#### `StridedInterval.bitwise_or(t)`

Binary operation: logical or

**Parameters:**

- **b** – The other operand

- **t** (*StridedInterval*)

**Return type:**

`StridedInterval`

**Returns:**

self | b

This implementation combines the approaches used by ‘WYSINWYX: what you see is not what you execute’ paper and ‘Signedness-Agnostic Program Analysis: Precise Integer Bounds for Low-Level Code’. The first paper provides an sound way to approximate the stride, whereas the second provides a way to calculate the or operation using wrapping intervals. Note that, even though according Warren’s work ‘Hacker’s delight’, one should follow different approaches to calculate the minimun/maximum values of an or operations according on the type of the operands (signed/unsigned). On the other other hand, by splitting the wrapping-intervals at the south pole, we can safely and soundly only use the Warren’s functions for unsigned integers.

#### `StridedInterval.bitwise_xor(t)`

Operation xor

**Parameters:**

**t** (`StridedInterval`) – The other operand.

**Return type:**

`StridedInterval`

#### `cardinality: int`

#### `StridedInterval.cast_low(*args, **kwargs)`

#### `complement: StridedInterval`

Return the complement of the interval Refer section 3.1 augmented for managing strides

**Returns:**

#### `StridedInterval.concat(b)`

**Return type:**

`StridedInterval`

**Parameters:**

**b** (*StridedInterval*)

#### `StridedInterval.copy()`

**Return type:**

`StridedInterval`

#### `StridedInterval.diop_natural_solution_linear(c, a, b)`

It finds the fist natural solution of the diophantine equation a*x + b*y = c. Some lines of this code are taken from the project sympy.

**Parameters:**

- **c** (`int`) – constant

- **a** (`int`) – quotient of x

- **b** (`int`) – quotient of y

**Return type:**

`tuple`[`int` | `None`, `int` | `None`]

**Returns:**

the first natural solution of the diophatine equation

#### `StridedInterval.empty(bits)`

**Return type:**

`StridedInterval`

**Parameters:**

**bits** (*int*)

#### `StridedInterval.eq(o)`

Equal

**Parameters:**

**o** (`StridedInterval`) – The ohter operand

**Return type:**

`BoolResult`

**Returns:**

TrueResult(), FalseResult(), or MaybeResult()

#### `StridedInterval.eval(n, signed=False)`

Evaluate this StridedInterval to obtain a list of concrete integers.

**Parameters:**

- **n** (`int`) – Upper bound for the number of concrete integers

- **signed** (`bool`) – Treat this StridedInterval as signed or unsigned

**Return type:**

`list`[`int`]

**Returns:**

A list of at most n concrete integers

#### `StridedInterval.extended_euclid(a, b)`

It calculates the GCD of a and b, and two values x and y such that: a*x + b*y = GCD(a,b). This code has been taken from the project sympy.

**Parameters:**

- **a** (`int`) – first integer

- **b** (`int`) – second integer

**Return type:**

`tuple`[`int`, `int`, `int`]

**Returns:**

x,y and the GCD of a and b

#### `StridedInterval.extract(*args, **kwargs)`

#### `StridedInterval.highbit(k)`

**Return type:**

`int`

**Parameters:**

**k** (*int*)

#### `StridedInterval.identical(o)`

Used to make exact comparisons between two StridedIntervals. Usually it is only used in test cases.

**Parameters:**

**o** (`StridedInterval`) – The other StridedInterval to compare with.

**Return type:**

`bool`

**Returns:**

True if they are exactly same, False otherwise.

#### `StridedInterval.intersection(b)`

**Return type:**

`StridedInterval`

**Parameters:**

**b** (*StridedInterval*)

#### `is_empty`

The same as is_bottom :return: True/False

#### `is_integer`

If this is an integer, i.e. self.lower_bound == self.upper_bound.

**Returns:**

True if this is an integer, False otherwise

#### `is_interval`

#### `is_top`

If this is a TOP value.

**Returns:**

True if this is a TOP

#### `StridedInterval.least_upper_bound(*intervals_to_join)`

Pseudo least upper bound. Join the given set of intervals into a big interval. The resulting strided interval is the one which in all the possible joins of the presented SI, presented the least number of values.

The number of joins to compute is linear with the number of intervals to join.

Draft of proof: Considering three generic SI (a,b, and c) ordered from their lower bounds, such that a.lower_bund <= b.lower_bound <= c.lower_bound, where <= is the lexicographic less or equal. The only joins which have sense to compute are: * a U b U c * b U c U a * c U a U b

All the other combinations fall in either one of these cases. For example: b U a U c does not make make sense to be calculated. In fact, if one draws this union, the result is exactly either (b U c U a) or (a U b U c) or (c U a U b). :type intervals_to_join: `StridedInterval` :param intervals_to_join: Intervals to join :rtype: `StridedInterval` :return: Interval that contains all intervals

**Parameters:**

**intervals_to_join** (*StridedInterval*)

**Return type:**

*StridedInterval*

#### `StridedInterval.lower(bits, i, stride)`

**Return type:**

`int`

**Returns:**

**Parameters:**

- **bits** (*int*)

- **i** (*int*)

- **stride** (*int*)

#### `lower_bound`

#### `StridedInterval.lshift(*args, **kwargs)`

#### `StridedInterval.max(*args, **kwargs)`

#### `StridedInterval.max_int(k)`

**Return type:**

`int`

**Parameters:**

**k** (*int*)

#### `StridedInterval.min(*args, **kwargs)`

#### `StridedInterval.min_bits(val, max_bits=None)`

**Return type:**

`int`

**Parameters:**

- **val** (*int*)

- **max_bits** (*int** | **None*)

#### `StridedInterval.min_int(k)`

**Return type:**

`int`

**Parameters:**

**k** (*int*)

#### `StridedInterval.mul(o)`

Binary operation: multiplication

**Parameters:**

**o** (`StridedInterval`) – The other operand

**Return type:**

`StridedInterval`

**Returns:**

self * o

#### `n_values`

#### `name: str`

#### `StridedInterval.nameless_copy()`

**Return type:**

`StridedInterval`

#### `StridedInterval.neg(*args, **kwargs)`

#### `StridedInterval.normalize()`

**Return type:**

`StridedInterval`

#### `StridedInterval.pseudo_join(s, b, smart_join=True)`

It two intervals in a way that the resulting SI is the one that has the least SI cardinality (i.e., which represents the least number of elements) possible if the smart_join flag is enabled, otherwise it just joins the SI according the order they are passed to the function.

The pseudo-join operation is not associative in wrapping intervals (please refer to section 3.1 paper ‘Signedness-Agnostic Program Analysis: Precise Integer Bounds for Low-Level Code’), Therefore the join of three WI may give us different results according on the order we join them. All of the results will be sound, though.

Please use the function least_upper_bound as a stub.

**Parameters:**

- **s** (`StridedInterval`) – The first SI

- **b** (`StridedInterval`) – The other SI.

- **smart_join** (`bool`) – Enable the smart join behavior. If this flag is set, this function joins the two SI in a way that the resulting Si has least number of elements (more precise). If it is unset, this function will join the two SI according on the order they are passed to the function.

**Return type:**

`StridedInterval`

**Returns:**

A new StridedInterval

#### `StridedInterval.reverse()`

This is a delayed reversing function. All it really does is to invert the _reversed property of this StridedInterval object.

**Returns:**

None

#### `reversed: bool`

#### `StridedInterval.rshift_arithmetic(*args, **kwargs)`

#### `StridedInterval.rshift_logical(*args, **kwargs)`

#### `StridedInterval.sdiv(o)`

Binary operation: signed division

**Parameters:**

**o** (`StridedInterval`) – The divisor

**Return type:**

`StridedInterval`

**Returns:**

(self / o) in signed arithmetic

#### `StridedInterval.sign(a)`

**Return type:**

`int`

**Parameters:**

**a** (*int*)

#### `StridedInterval.sign_extend(*args, **kwargs)`

#### `StridedInterval.signed_max_int(k)`

**Return type:**

`int`

**Parameters:**

**k** (*int*)

#### `StridedInterval.signed_min_int(k)`

**Return type:**

`int`

**Parameters:**

**k** (*int*)

#### `StridedInterval.solution(b)`

Checks whether an integer is solution of the current strided Interval :type b: `int` :param b: integer to check :rtype: `bool` :return: True if b belongs to the current Strided Interval, False otherwhise

**Parameters:**

**b** (*int*)

**Return type:**

bool

#### `stride`

#### `StridedInterval.sub(b)`

Binary operation: sub

**Parameters:**

**b** (`StridedInterval`) – The other operand

**Return type:**

`StridedInterval`

**Returns:**

self - b

#### `StridedInterval.top(bits, name=None, uninitialized=False)`

Get a TOP StridedInterval.

**Return type:**

`StridedInterval`

**Returns:**

**Parameters:**

- **bits** (*int*)

- **name** (*str** | **None*)

- **uninitialized** (*bool*)

#### `StridedInterval.udiv(o)`

Binary operation: unsigned division

**Parameters:**

**o** (`StridedInterval`) – The divisor

**Return type:**

`StridedInterval`

**Returns:**

(self / o) in unsigned arithmetic

#### `StridedInterval.union(b)`

The union operation. It might return a DiscreteStridedIntervalSet to allow for better precision in analysis.

**Parameters:**

**b** (`StridedInterval`) – Operand

**Return type:**

`StridedInterval`

**Returns:**

A new DiscreteStridedIntervalSet, or a new StridedInterval.

#### `StridedInterval.upper(bits, i, stride)`

**Return type:**

`int`

**Returns:**

**Parameters:**

- **bits** (*int*)

- **i** (*int*)

- **stride** (*int*)

#### `upper_bound`

#### `StridedInterval.widen(b)`

**Return type:**

`StridedInterval`

**Parameters:**

**b** (*StridedInterval*)

#### `StridedInterval.zero_extend(*args, **kwargs)`

### `TrueResult()`

Return a BoolResult representing the value True.

**Return type:**

`BoolResult`

### `ValueSet`

Bases: `object`

ValueSet is a mapping between memory regions and corresponding offsets.

#### `ValueSet.LShR(other)`

#### `ValueSet.SGE(_)`

#### `ValueSet.SGT(_)`

#### `ValueSet.SLE(_)`

#### `ValueSet.SLT(_)`

#### `ValueSet.UGE(_)`

#### `ValueSet.UGT(_)`

#### `ValueSet.ULE(_)`

#### `ValueSet.ULT(_)`

#### `ValueSet.__init__(name=None, region=None, region_base_addr=None, bits=None, val=None)`

Constructor.

**Parameters:**

- **name** (*str*) – Name of this ValueSet object. Only for debugging purposes.

- **region** (*str*) – Region ID.

- **region_base_addr** (*int*) – Base address of the region.

- **bits** (*int*) – Size of the ValueSet.

- **val** – an initial offset

#### `bits`

#### `cardinality`

#### `ValueSet.concat(b)`

#### `ValueSet.copy()`

Make a copy of self and return.

**Returns:**

A new ValueSet object.

**Return type:**

ValueSet

#### `ValueSet.empty(bits)`

#### `ValueSet.eval(n, signed=False)`

#### `ValueSet.extract(high_bit, low_bit)`

Operation extract

- **A cheap hack is implemented: a copy of self is returned if (high_bit - low_bit + 1 == self.bits), which is a**

ValueSet instance. Otherwise a StridedInterval is returned.

**Parameters:**

- **high_bit**

- **low_bit**

**Returns:**

A ValueSet or a StridedInterval

#### `ValueSet.get_si(region)`

#### `ValueSet.identical(o)`

Used to make exact comparisons between two ValueSets.

**Parameters:**

**o** – The other ValueSet to compare with.

**Returns:**

True if they are exactly same, False otherwise.

#### `ValueSet.intersection(b)`

#### `is_empty`

#### `ValueSet.items()`

#### `ValueSet.max(signed=False)`

The maximum integer value of a value-set. It is only defined when there is exactly one region.

**Returns:**

A integer that represents the maximum integer value of this value-set.

**Return type:**

int

#### `ValueSet.min(signed=False)`

The minimum integer value of a value-set. It is only defined when there is exactly one region.

**Returns:**

A integer that represents the minimum integer value of this value-set.

**Return type:**

int

#### `name`

#### `regions`

#### `ValueSet.reverse()`

#### `reversed`

#### `ValueSet.size()`

#### `ValueSet.stridedinterval()`

#### `ValueSet.union(b)`

#### `ValueSet.widen(b)`

## Frontends

### `CompositeFrontend`

Bases: `ConstrainedFrontend`

Composite Solver splits constraints into independent sets, allowing caching to be done on a per-set basis. Additionally, by allowing constraints to be solved independently, the solver can be more efficient in some cases (“divide and conquer”).

For example, the constraints (a==b, b==1, c==4) would be split into two sets: one containing a==b and b==1, and the other containing c==4.

#### `CompositeFrontend.__init__(template_frontend, track=False, **kwargs)`

#### `CompositeFrontend.batch_eval(exprs, n, extra_constraints=(), exact=None)`

Evaluates exprs, returning a list of tuples (one tuple of n solutions for expression).

**Parameters:**

- **exprs** – expressions

- **n** – the number of solutions to return

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

list of tuples of python primitives representing results

#### `CompositeFrontend.check_satisfiability(extra_constraints=(), exact=None)`

Checks the satisfiability of stored constraints conjunction.

**Parameters:**

- **extra_constraints** – extra constraints to consider when checking satisfiability

- **exact** – whether or not to perform exact checking. Ignored by non-approximating backends.

**Returns:**

‘SAT’ if the conjunction is satisfiable otherwise ‘UNSAT’

#### `CompositeFrontend.downsize()`

#### `CompositeFrontend.eval(e, n, extra_constraints=(), exact=None)`

Evaluates expression e, returning a tuple of n solutions.

**Parameters:**

- **e** – the expression

- **n** – the number of solutions to return

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

tuple of python primitives representing results

#### `CompositeFrontend.finalize()`

#### `CompositeFrontend.is_false(e, extra_constraints=(), exact=None)`

Checks if e can only (and TRIVIALLY) evaluate to False. If this function returns True, then the expression cannot ever be True, regardless of constraints or anything else. If the expression returns False, then the expression might STILL not ever be True; it’s just that we can’t trivially prove it. In other words, a return value of False gives you no information whatsoever.

**Parameters:**

- **e** – the expression

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

True if it can only evaluate to False otherwise False

#### `CompositeFrontend.is_true(e, extra_constraints=(), exact=None)`

Checks if e can only (and TRIVIALLY) evaluate to True. If this function returns True, then the expression cannot ever be False, regardless of constraints or anything else. If the expression returns False, then the expression might STILL not ever be False; it’s just that we can’t trivially prove it. In other words, a return value of False gives you no information whatsoever.

**Parameters:**

- **e** – the expression

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

True if it can only evaluate to True otherwise False

#### `CompositeFrontend.max(e, extra_constraints=(), signed=False, exact=None)`

Evaluates e, returning its max possible value.

**Parameters:**

- **e** – the expression

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **signed** – whether the value should be treated as a signed integer

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

max possible value

#### `max_memory`

#### `CompositeFrontend.merge(others, merge_conditions, common_ancestor=None)`

#### `CompositeFrontend.min(e, extra_constraints=(), signed=False, exact=None)`

Evaluates e, returning its min possible value.

**Parameters:**

- **e** – the expression

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **signed** – whether the value should be treated as a signed integer

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

min possible value

#### `CompositeFrontend.satisfiable(extra_constraints=(), exact=None)`

Checks if stored constraints conjunction is satisfiable.

**Parameters:**

- **extra_constraints** – extra constraints to consider when checking satisfiability

- **exact** – whether or not to perform exact checking. Ignored by non-approximating backends.

**Returns:**

True if the conjunction is satisfiable otherwise False

#### `CompositeFrontend.simplify()`

Simplifies the stored constraints conjunction.

#### `CompositeFrontend.solution(e, v, extra_constraints=(), exact=None)`

Checks if v is a possible solution to e.

**Parameters:**

- **e** – the expression

- **v** – the value

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

True if it is a possible solution otherwise False

#### `CompositeFrontend.split()`

#### `timeout`

#### `CompositeFrontend.unsat_core(extra_constraints=())`

#### `variables`

### `Frontend`

Bases: `object`

Frontend is the base class for all claripy Solvers, which are the interfaces to the backend constraint solvers.

#### `Frontend.__init__()`

#### `Frontend.add(constraints, invalidate_cache=True)`

Adds constraint(s) to constraints list.

**Parameters:**

**constraints** – constraint(s) to add

**Returns:**

#### `Frontend.batch_eval(exprs, n, extra_constraints=(), exact=None)`

Evaluates exprs, returning a list of tuples (one tuple of n solutions for expression).

**Parameters:**

- **exprs** – expressions

- **n** – the number of solutions to return

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

list of tuples of python primitives representing results

#### `Frontend.blank_copy()`

#### `Frontend.branch()`

#### `Frontend.check_satisfiability(extra_constraints=(), exact=None)`

Checks the satisfiability of stored constraints conjunction.

**Parameters:**

- **extra_constraints** – extra constraints to consider when checking satisfiability

- **exact** – whether or not to perform exact checking. Ignored by non-approximating backends.

**Returns:**

‘SAT’ if the conjunction is satisfiable otherwise ‘UNSAT’

#### `Frontend.combine(others)`

#### `Frontend.downsize()`

#### `Frontend.eval(e, n, extra_constraints=(), exact=None)`

Evaluates expression e, returning a tuple of n solutions.

**Parameters:**

- **e** – the expression

- **n** – the number of solutions to return

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

tuple of python primitives representing results

#### `Frontend.eval_to_ast(e, n, extra_constraints=(), exact=None)`

Evaluates expression e, returning a list of n concrete ASTs.

**Parameters:**

- **e** – the expression

- **n** – the number of ASTs to return

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

list of concrete ASTs

#### `Frontend.finalize()`

#### `Frontend.is_false(e, extra_constraints=(), exact=None)`

Checks if e can only (and TRIVIALLY) evaluate to False. If this function returns True, then the expression cannot ever be True, regardless of constraints or anything else. If the expression returns False, then the expression might STILL not ever be True; it’s just that we can’t trivially prove it. In other words, a return value of False gives you no information whatsoever.

**Parameters:**

- **e** – the expression

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

True if it can only evaluate to False otherwise False

#### `Frontend.is_true(e, extra_constraints=(), exact=None)`

Checks if e can only (and TRIVIALLY) evaluate to True. If this function returns True, then the expression cannot ever be False, regardless of constraints or anything else. If the expression returns False, then the expression might STILL not ever be False; it’s just that we can’t trivially prove it. In other words, a return value of False gives you no information whatsoever.

**Parameters:**

- **e** – the expression

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

True if it can only evaluate to True otherwise False

#### `Frontend.max(e, extra_constraints=(), signed=False, exact=None)`

Evaluates e, returning its max possible value.

**Parameters:**

- **e** – the expression

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **signed** – whether the value should be treated as a signed integer

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

max possible value

#### `Frontend.merge(others, merge_conditions, common_ancestor=None)`

#### `Frontend.min(e, extra_constraints=(), signed=False, exact=None)`

Evaluates e, returning its min possible value.

**Parameters:**

- **e** – the expression

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **signed** – whether the value should be treated as a signed integer

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

min possible value

#### `Frontend.satisfiable(extra_constraints=(), exact=None)`

Checks if stored constraints conjunction is satisfiable.

**Parameters:**

- **extra_constraints** – extra constraints to consider when checking satisfiability

- **exact** – whether or not to perform exact checking. Ignored by non-approximating backends.

**Returns:**

True if the conjunction is satisfiable otherwise False

#### `Frontend.simplify()`

Simplifies the stored constraints conjunction.

#### `Frontend.solution(e, v, extra_constraints=(), exact=None)`

Checks if v is a possible solution to e.

**Parameters:**

- **e** – the expression

- **v** – the value

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

True if it is a possible solution otherwise False

#### `Frontend.split()`

### `FullFrontend`

Bases: `ConstrainedFrontend`

FullFrontend is a frontend that supports all claripy operations and is backed by a full solver backend.

#### `FullFrontend.__init__(solver_backend, timeout=None, max_memory=None, track=False, **kwargs)`

#### `FullFrontend.batch_eval(exprs, n, extra_constraints=(), exact=None)`

Evaluates exprs, returning a list of tuples (one tuple of n solutions for expression).

**Parameters:**

- **exprs** – expressions

- **n** – the number of solutions to return

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

list of tuples of python primitives representing results

#### `FullFrontend.check_satisfiability(extra_constraints=(), exact=None)`

Checks the satisfiability of stored constraints conjunction.

**Parameters:**

- **extra_constraints** – extra constraints to consider when checking satisfiability

- **exact** – whether or not to perform exact checking. Ignored by non-approximating backends.

**Return type:**

`str`

**Returns:**

‘SAT’ if the conjunction is satisfiable otherwise ‘UNSAT’

#### `FullFrontend.downsize()`

**Return type:**

`None`

#### `FullFrontend.eval(e, n, extra_constraints=(), exact=None)`

Evaluates expression e, returning a tuple of n solutions.

**Parameters:**

- **e** – the expression

- **n** – the number of solutions to return

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Return type:**

`tuple`[`Any`, `...`]

**Returns:**

tuple of python primitives representing results

#### `FullFrontend.is_false(e, extra_constraints=(), exact=None)`

Checks if e can only (and TRIVIALLY) evaluate to False. If this function returns True, then the expression cannot ever be True, regardless of constraints or anything else. If the expression returns False, then the expression might STILL not ever be True; it’s just that we can’t trivially prove it. In other words, a return value of False gives you no information whatsoever.

**Parameters:**

- **e** (`Bool`) – the expression

- **extra_constraints** (`tuple`[`Bool`, `...`]) – extra constraints to consider when performing the evaluation

- **exact** (`bool` | `None`) – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Return type:**

`bool`

**Returns:**

True if it can only evaluate to False otherwise False

#### `FullFrontend.is_true(e, extra_constraints=(), exact=None)`

Checks if e can only (and TRIVIALLY) evaluate to True. If this function returns True, then the expression cannot ever be False, regardless of constraints or anything else. If the expression returns False, then the expression might STILL not ever be False; it’s just that we can’t trivially prove it. In other words, a return value of False gives you no information whatsoever.

**Parameters:**

- **e** (`Bool`) – the expression

- **extra_constraints** (`tuple`[`Bool`, `...`]) – extra constraints to consider when performing the evaluation

- **exact** (`bool` | `None`) – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Return type:**

`bool`

**Returns:**

True if it can only evaluate to True otherwise False

#### `FullFrontend.max(e, extra_constraints=(), signed=False, exact=None)`

Evaluates e, returning its max possible value.

**Parameters:**

- **e** – the expression

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **signed** – whether the value should be treated as a signed integer

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

max possible value

#### `FullFrontend.merge(others, merge_conditions, common_ancestor=None)`

**Return type:**

`tuple`[`bool`, `Self`]

#### `FullFrontend.min(e, extra_constraints=(), signed=False, exact=None)`

Evaluates e, returning its min possible value.

**Parameters:**

- **e** – the expression

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **signed** – whether the value should be treated as a signed integer

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

min possible value

#### `FullFrontend.satisfiable(extra_constraints=(), exact=None)`

Checks if stored constraints conjunction is satisfiable.

**Parameters:**

- **extra_constraints** (`Iterable`[`Bool`]) – extra constraints to consider when checking satisfiability

- **exact** (`bool` | `None`) – whether or not to perform exact checking. Ignored by non-approximating backends.

**Return type:**

`bool`

**Returns:**

True if the conjunction is satisfiable otherwise False

#### `FullFrontend.simplify()`

Simplifies the stored constraints conjunction.

#### `FullFrontend.solution(e, v, extra_constraints=(), exact=None)`

Checks if v is a possible solution to e.

**Parameters:**

- **e** – the expression

- **v** – the value

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

True if it is a possible solution otherwise False

#### `FullFrontend.unsat_core(extra_constraints=())`

**Return type:**

`Iterable`[`Bool`]

**Parameters:**

**extra_constraints** (*tuple**[**Bool**, **...**]*)

### `HybridFrontend`

Bases: `Frontend`

HybridFrontend is a frontend that uses two backends, one exact and one approximate, to solve constraints.

In practice this allows there to be a solver that can use the VSA backend or the Z3 backend depending on the constraints.

#### `HybridFrontend.__init__(exact_frontend, approximate_frontend, approximate_first=False, **kwargs)`

#### `HybridFrontend.batch_eval(exprs, n, extra_constraints=(), exact=None)`

Evaluates exprs, returning a list of tuples (one tuple of n solutions for expression).

**Parameters:**

- **exprs** – expressions

- **n** – the number of solutions to return

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

list of tuples of python primitives representing results

#### `HybridFrontend.combine(others)`

#### `constraints`

#### `HybridFrontend.downsize()`

#### `HybridFrontend.eval(e, n, extra_constraints=(), exact=None)`

Evaluates expression e, returning a tuple of n solutions.

**Parameters:**

- **e** – the expression

- **n** – the number of solutions to return

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

tuple of python primitives representing results

#### `HybridFrontend.eval_to_ast(e, n, extra_constraints=(), exact=None)`

Evaluates expression e, returning a list of n concrete ASTs.

**Parameters:**

- **e** – the expression

- **n** – the number of ASTs to return

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

list of concrete ASTs

#### `HybridFrontend.finalize()`

#### `HybridFrontend.is_false(e, extra_constraints=(), exact=None)`

Checks if e can only (and TRIVIALLY) evaluate to False. If this function returns True, then the expression cannot ever be True, regardless of constraints or anything else. If the expression returns False, then the expression might STILL not ever be True; it’s just that we can’t trivially prove it. In other words, a return value of False gives you no information whatsoever.

**Parameters:**

- **e** – the expression

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

True if it can only evaluate to False otherwise False

#### `HybridFrontend.is_true(e, extra_constraints=(), exact=None)`

Checks if e can only (and TRIVIALLY) evaluate to True. If this function returns True, then the expression cannot ever be False, regardless of constraints or anything else. If the expression returns False, then the expression might STILL not ever be False; it’s just that we can’t trivially prove it. In other words, a return value of False gives you no information whatsoever.

**Parameters:**

- **e** – the expression

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

True if it can only evaluate to True otherwise False

#### `HybridFrontend.max(e, extra_constraints=(), signed=False, exact=None)`

Evaluates e, returning its max possible value.

**Parameters:**

- **e** – the expression

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **signed** – whether the value should be treated as a signed integer

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

max possible value

#### `HybridFrontend.merge(others, merge_conditions, common_ancestor=None)`

#### `HybridFrontend.min(e, extra_constraints=(), signed=False, exact=None)`

Evaluates e, returning its min possible value.

**Parameters:**

- **e** – the expression

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **signed** – whether the value should be treated as a signed integer

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

min possible value

#### `HybridFrontend.satisfiable(extra_constraints=(), exact=None)`

Checks if stored constraints conjunction is satisfiable.

**Parameters:**

- **extra_constraints** – extra constraints to consider when checking satisfiability

- **exact** – whether or not to perform exact checking. Ignored by non-approximating backends.

**Returns:**

True if the conjunction is satisfiable otherwise False

#### `HybridFrontend.simplify()`

Simplifies the stored constraints conjunction.

#### `HybridFrontend.solution(e, v, extra_constraints=(), exact=None)`

Checks if v is a possible solution to e.

**Parameters:**

- **e** – the expression

- **v** – the value

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

True if it is a possible solution otherwise False

#### `HybridFrontend.split()`

#### `HybridFrontend.unsat_core(extra_constraints=())`

#### `variables`

### `LightFrontend`

Bases: `ConstrainedFrontend`

LightFrontend is an extremely simple frontend that is used primarily for the purpose of quickly evaluating expressions using the concrete and VSA backends.

#### `LightFrontend.__init__(solver_backend, **kwargs)`

#### `LightFrontend.batch_eval(exprs, n, extra_constraints=(), exact=None)`

Evaluates exprs, returning a list of tuples (one tuple of n solutions for expression).

**Parameters:**

- **exprs** – expressions

- **n** – the number of solutions to return

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

list of tuples of python primitives representing results

#### `LightFrontend.eval(e, n, extra_constraints=(), exact=None)`

Evaluates expression e, returning a tuple of n solutions.

**Parameters:**

- **e** – the expression

- **n** – the number of solutions to return

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

tuple of python primitives representing results

#### `LightFrontend.is_false(e, extra_constraints=(), exact=None)`

Checks if e can only (and TRIVIALLY) evaluate to False. If this function returns True, then the expression cannot ever be True, regardless of constraints or anything else. If the expression returns False, then the expression might STILL not ever be True; it’s just that we can’t trivially prove it. In other words, a return value of False gives you no information whatsoever.

**Parameters:**

- **e** – the expression

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

True if it can only evaluate to False otherwise False

#### `LightFrontend.is_true(e, extra_constraints=(), exact=None)`

Checks if e can only (and TRIVIALLY) evaluate to True. If this function returns True, then the expression cannot ever be False, regardless of constraints or anything else. If the expression returns False, then the expression might STILL not ever be False; it’s just that we can’t trivially prove it. In other words, a return value of False gives you no information whatsoever.

**Parameters:**

- **e** – the expression

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

True if it can only evaluate to True otherwise False

#### `LightFrontend.max(e, extra_constraints=(), signed=False, exact=None)`

Evaluates e, returning its max possible value.

**Parameters:**

- **e** – the expression

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **signed** – whether the value should be treated as a signed integer

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

max possible value

#### `LightFrontend.merge(others, merge_conditions, common_ancestor=None)`

#### `LightFrontend.min(e, extra_constraints=(), signed=False, exact=None)`

Evaluates e, returning its min possible value.

**Parameters:**

- **e** – the expression

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **signed** – whether the value should be treated as a signed integer

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

min possible value

#### `LightFrontend.satisfiable(extra_constraints=(), exact=None)`

Checks if stored constraints conjunction is satisfiable.

**Parameters:**

- **extra_constraints** – extra constraints to consider when checking satisfiability

- **exact** – whether or not to perform exact checking. Ignored by non-approximating backends.

**Returns:**

True if the conjunction is satisfiable otherwise False

#### `LightFrontend.solution(e, v, extra_constraints=(), exact=None)`

Checks if v is a possible solution to e.

**Parameters:**

- **e** – the expression

- **v** – the value

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

True if it is a possible solution otherwise False

### `ReplacementFrontend`

Bases: `ConstrainedFrontend`

ReplacementFrontend is a frontend that allows for the replacement symbolic constraints with concrete solutions. This is useful for simplifying constraints and speeding up solving time.

#### `ReplacementFrontend.__init__(actual_frontend, allow_symbolic=None, replacements=None, replacement_cache=None, unsafe_replacement=None, complex_auto_replace=None, auto_replace=None, replace_constraints=None, **kwargs)`

#### `ReplacementFrontend.add_replacement(old, new, invalidate_cache=True, replace=True, promote=True)`

#### `ReplacementFrontend.batch_eval(exprs, n, extra_constraints=(), exact=None)`

Evaluates exprs, returning a list of tuples (one tuple of n solutions for expression).

**Parameters:**

- **exprs** – expressions

- **n** – the number of solutions to return

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

list of tuples of python primitives representing results

#### `ReplacementFrontend.clear_replacements()`

#### `ReplacementFrontend.downsize()`

#### `ReplacementFrontend.eval(e, n, extra_constraints=(), exact=None)`

Evaluates expression e, returning a tuple of n solutions.

**Parameters:**

- **e** – the expression

- **n** – the number of solutions to return

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

tuple of python primitives representing results

#### `ReplacementFrontend.is_false(e, extra_constraints=(), exact=None)`

Checks if e can only (and TRIVIALLY) evaluate to False. If this function returns True, then the expression cannot ever be True, regardless of constraints or anything else. If the expression returns False, then the expression might STILL not ever be True; it’s just that we can’t trivially prove it. In other words, a return value of False gives you no information whatsoever.

**Parameters:**

- **e** – the expression

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

True if it can only evaluate to False otherwise False

#### `ReplacementFrontend.is_true(e, extra_constraints=(), exact=None)`

Checks if e can only (and TRIVIALLY) evaluate to True. If this function returns True, then the expression cannot ever be False, regardless of constraints or anything else. If the expression returns False, then the expression might STILL not ever be False; it’s just that we can’t trivially prove it. In other words, a return value of False gives you no information whatsoever.

**Parameters:**

- **e** – the expression

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

True if it can only evaluate to True otherwise False

#### `ReplacementFrontend.max(e, extra_constraints=(), signed=False, exact=None)`

Evaluates e, returning its max possible value.

**Parameters:**

- **e** – the expression

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **signed** – whether the value should be treated as a signed integer

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

max possible value

#### `ReplacementFrontend.min(e, extra_constraints=(), signed=False, exact=None)`

Evaluates e, returning its min possible value.

**Parameters:**

- **e** – the expression

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **signed** – whether the value should be treated as a signed integer

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

min possible value

#### `ReplacementFrontend.remove_replacements(old_entries)`

#### `ReplacementFrontend.satisfiable(extra_constraints=(), exact=None)`

Checks if stored constraints conjunction is satisfiable.

**Parameters:**

- **extra_constraints** – extra constraints to consider when checking satisfiability

- **exact** – whether or not to perform exact checking. Ignored by non-approximating backends.

**Returns:**

True if the conjunction is satisfiable otherwise False

#### `ReplacementFrontend.solution(e, v, extra_constraints=(), exact=None)`

Checks if v is a possible solution to e.

**Parameters:**

- **e** – the expression

- **v** – the value

- **extra_constraints** – extra constraints to consider when performing the evaluation

- **exact** – whether or not to perform an exact evaluation. Ignored by non-approximating backends.

**Returns:**

True if it is a possible solution otherwise False

### `Solver`

Bases: `ConcreteHandlerMixin`, `EagerResolutionMixin`, `ConstraintFilterMixin`, `ConstraintDeduplicatorMixin`, `SimplifySkipperMixin`, `SatCacheMixin`, `ModelCacheMixin`, `ConstraintExpansionMixin`, `SimplifyHelperMixin`, `FullFrontend`

Solver is the default Claripy frontend. It uses Z3 as the backend solver by default.

#### `Solver.__init__(backend=<claripy.backends.backend_z3.BackendZ3 object>, **kwargs)`

### `SolverCacheless`

Bases: `ConcreteHandlerMixin`, `EagerResolutionMixin`, `ConstraintFilterMixin`, `ConstraintDeduplicatorMixin`, `SimplifySkipperMixin`, `FullFrontend`

SolverCacheless is a Solver without caching. It uses Z3 as the backend solver by default.

#### `SolverCacheless.__init__(backend=<claripy.backends.backend_z3.BackendZ3 object>, **kwargs)`

### `SolverReplacement`

Bases: `ConcreteHandlerMixin`, `ConstraintDeduplicatorMixin`, `ReplacementFrontend`

SolverReplacement is a frontend wrapper that replaces constraints with their solutions.

#### `SolverReplacement.__init__(actual_frontend=None, **kwargs)`

### `SolverHybrid`

Bases: `ConcreteHandlerMixin`, `EagerResolutionMixin`, `ConstraintFilterMixin`, `ConstraintDeduplicatorMixin`, `SimplifySkipperMixin`, `HybridFrontend`

SolverHybrid is a frontend that uses an exact solver and an approximate solver.

#### `SolverHybrid.__init__(exact_frontend=None, approximate_frontend=None, complex_auto_replace=True, replace_constraints=True, track=False, approximate_first=False, **kwargs)`

### `SolverVSA`

Bases: `ConcreteHandlerMixin`, `ConstraintFilterMixin`, `LightFrontend`

SolverVSA is a thin frontend to the VSA backend solver.

#### `SolverVSA.__init__(**kwargs)`

### `SolverConcrete`

Bases: `ConcreteHandlerMixin`, `ConstraintFilterMixin`, `LightFrontend`

SolverConcrete is a thin frontend to the Concrete backend solver.

#### `SolverConcrete.__init__(**kwargs)`

### `SolverStrings`

Bases: `ConcreteHandlerMixin`, `ConstraintFilterMixin`, `ConstraintDeduplicatorMixin`, `EagerResolutionMixin`, `FullFrontend`

SolverStrings is a frontend that uses Z3 to solve string constraints.

#### `SolverStrings.__init__(*args, backend=<claripy.backends.backend_z3.BackendZ3 object>, **kwargs)`

### `SolverCompositeChild`

Bases: `ConstraintDeduplicatorMixin`, `SatCacheMixin`, `SimplifySkipperMixin`, `ModelCacheMixin`, `FullFrontend`

SolverCompositeChild is a frontend that is used as a child in a SolverComposite.

#### `SolverCompositeChild.__init__(backend=<claripy.backends.backend_z3.BackendZ3 object>, **kwargs)`

### `SolverComposite`

Bases: `ConcreteHandlerMixin`, `EagerResolutionMixin`, `ConstraintFilterMixin`, `ConstraintDeduplicatorMixin`, `SatCacheMixin`, `SimplifySkipperMixin`, `SimplifyHelperMixin`, `ConstraintExpansionMixin`, `CompositedCacheMixin`, `CompositeFrontend`

SolverComposite is a frontend that composes multiple templated frontends.

#### `SolverComposite.__init__(template_solver=None, track=False, **kwargs)`

## Frontend Mixins

## Annotations

### `Annotation`

Bases: `object`

Annotations are used to achieve claripy’s goal of being an arithmetic instrumentation engine. They provide a means to pass extra information to the claripy backends.

#### `eliminatable: bool`

Returns whether this annotation can be eliminated in a simplification.

**Returns:**

True if eliminatable, False otherwise

#### `relocatable: bool`

Returns whether this annotation can be relocated in a simplification.

**Returns:**

True if it can be relocated, false otherwise.

#### `Annotation.relocate(src, dst)`

This is called when an annotation has to be relocated because of simplifications.

Consider the following case:

> x = claripy.BVS(‘x’, 32) zero = claripy.BVV(0, 32).add_annotation(your_annotation) y = x + zero

Here, one of three things can happen:

> 1. if your_annotation.eliminatable is True, the simplifiers will simply eliminate your_annotation along with zero and y is x will hold

2. elif your_annotation.relocatable is False, the simplifier will abort and y will never be simplified

3. elif your_annotation.relocatable is True, the simplifier will run, determine that the simplified result of x + zero will be x. It will then call your_annotation.relocate(zero, x) to move the annotation away from the AST that is about to be eliminated.

**Parameters:**

- **src** (`Base`) – the old AST that was eliminated in the simplification

- **dst** (`Base`) – the new AST (the result of a simplification)

**Returns:**

the annotation that will be applied to dst

### `SimplificationAvoidanceAnnotation`

Bases: `Annotation`

SimplificationAvoidanceAnnotation is an annotation that prevents simplification of an AST.

#### `eliminatable`

Returns whether this annotation can be eliminated in a simplification.

**Returns:**

True if eliminatable, False otherwise

#### `relocatable`

Returns whether this annotation can be relocated in a simplification.

**Returns:**

True if it can be relocated, false otherwise.

### `StridedIntervalAnnotation`

Bases: `SimplificationAvoidanceAnnotation`

StridedIntervalAnnotation allows annotating a BVS to represent a strided interval.

**Parameters:**

- **stride** (*int*)

- **lower_bound** (*int*)

- **upper_bound** (*int*)

#### `StridedIntervalAnnotation.__init__(stride, lower_bound, upper_bound)`

**Parameters:**

- **stride** (*int*)

- **lower_bound** (*int*)

- **upper_bound** (*int*)

#### `stride: int`

#### `lower_bound: int`

#### `upper_bound: int`

### `RegionAnnotation`

Bases: `SimplificationAvoidanceAnnotation`

Use RegionAnnotation to annotate ASTs. Normally, an AST annotated by RegionAnnotations is treated as a ValueSet.

#### `RegionAnnotation.__init__(region_id, region_base_addr)`

### `UninitializedAnnotation`

Bases: `Annotation`

Use UninitializedAnnotation to annotate ASTs that are uninitialized.

#### `eliminatable: eliminatable = False`

#### `relocatable: relocatable = True`

## VSA

## Misc. Things

### `BVS(name, size, explicit_name=None, **kwargs)`

Creates a bit-vector symbol (i.e., a variable).

If you want to specify the maximum or minimum value of a normal symbol that is not part of value-set analysis, you should manually add constraints to that effect. **Do not use ``min`` and ``max`` for symbolic execution.**

**Parameters:**

- **name** – The name of the symbol.

- **size** – The size (in bits) of the bit-vector.

- **explicit_name** (*bool*) – If False, an identifier is appended to the name to ensure uniqueness.

**Return type:**

`BV`

**Returns:**

a BV object representing this symbol.

### `BVV(value, size=None, **kwargs)`

Creates a bit-vector value (i.e., a concrete value).

**Parameters:**

- **value** – The value. Either an integer or a bytestring. If it’s the latter, it will be interpreted as the bytes of a big-endian constant.

- **size** – The size (in bits) of the bit-vector. Optional if you provide a string, required for an integer.

**Return type:**

`BV`

**Returns:**

A BV object representing this value.

### `ESI(bits, **kwargs)`

### `FPS(name, sort, explicit_name=None)`

Creates a floating-point symbol.

**Parameters:**

- **name** – The name of the symbol

- **sort** – The sort of the floating point

- **explicit_name** – If False, an identifier is appended to the name to ensure uniqueness.

**Return type:**

`FP`

**Returns:**

An FP AST.

### `FPV(value, sort)`

Creates a concrete floating-point value.

**Parameters:**

- **value** – The value of the floating point.

- **sort** – The sort of the floating point.

**Return type:**

`FP`

**Returns:**

An FP AST.

### `RM`

Bases: `Enum`

Rounding modes for floating point operations.

See https://en.wikipedia.org/wiki/IEEE_754#Rounding_rules for more information.

#### `RM.default()`

#### `RM.pydecimal_equivalent_rounding_mode()`

#### `RM_NearestTiesEven: RM_NearestTiesEven = 'RM_RNE'`

#### `RM_NearestTiesAwayFromZero: RM_NearestTiesAwayFromZero = 'RM_RNA'`

#### `RM_TowardsZero: RM_TowardsZero = 'RM_RTZ'`

#### `RM_TowardsPositiveInf: RM_TowardsPositiveInf = 'RM_RTP'`

#### `RM_TowardsNegativeInf: RM_TowardsNegativeInf = 'RM_RTN'`

### `SGE(*args)`

### `SGT(*args)`

### `SI(name='unnamed', bits=0, lower_bound=None, upper_bound=None, stride=None, explicit_name=None)`

### `SLE(*args)`

### `SLT(*args)`

### `TSI(bits, name=None, explicit_name=None)`

### `UGE(*args)`

### `UGT(*args)`

### `ULE(*args)`

### `ULT(*args)`

### `VS(bits, region, region_base_addr, value)`

**Parameters:**

- **bits** (*int*)

- **region** (*str*)

- **region_base_addr** (*int*)

- **value** (*BV** | **int*)

### `And(*args)`

### `Annotation`

Bases: `object`

Annotations are used to achieve claripy’s goal of being an arithmetic instrumentation engine. They provide a means to pass extra information to the claripy backends.

#### `eliminatable: bool`

Returns whether this annotation can be eliminated in a simplification.

**Returns:**

True if eliminatable, False otherwise

#### `relocatable: bool`

Returns whether this annotation can be relocated in a simplification.

**Returns:**

True if it can be relocated, false otherwise.

#### `Annotation.relocate(src, dst)`

This is called when an annotation has to be relocated because of simplifications.

Consider the following case:

> x = claripy.BVS(‘x’, 32) zero = claripy.BVV(0, 32).add_annotation(your_annotation) y = x + zero

Here, one of three things can happen:

> 1. if your_annotation.eliminatable is True, the simplifiers will simply eliminate your_annotation along with zero and y is x will hold

2. elif your_annotation.relocatable is False, the simplifier will abort and y will never be simplified

3. elif your_annotation.relocatable is True, the simplifier will run, determine that the simplified result of x + zero will be x. It will then call your_annotation.relocate(zero, x) to move the annotation away from the AST that is about to be eliminated.

**Parameters:**

- **src** (`Base`) – the old AST that was eliminated in the simplification

- **dst** (`Base`) – the new AST (the result of a simplification)

**Returns:**

the annotation that will be applied to dst

### `BoolS(name, explicit_name=None)`

Creates a boolean symbol (i.e., a variable).

**Parameters:**

- **name** – The name of the symbol

- **explicit_name** – If False, an identifier is appended to the name to ensure uniqueness.

**Return type:**

`Bool`

**Returns:**

A Bool object representing this symbol.

### `BoolV(val)`

**Return type:**

`Bool`

### `ClaripyError`

Bases: `Exception`

### `ClaripyFrontendError`

Bases: `ClaripyError`

### `ClaripyOperationError`

Bases: `ClaripyASTError`

### `ClaripySolverInterruptError`

Bases: `ClaripyError`

### `ClaripyZeroDivisionError`

Bases: `ClaripyOperationError`, `ZeroDivisionError`

### `Concat(*args)`

### `Extract(*args)`

### `If(cond, true_value, false_value)`

### `IntToStr(*args)`

### `LShR(*args)`

### `Not(*args)`

### `Or(*args)`

### `RegionAnnotation`

Bases: `SimplificationAvoidanceAnnotation`

Use RegionAnnotation to annotate ASTs. Normally, an AST annotated by RegionAnnotations is treated as a ValueSet.

#### `RegionAnnotation.__init__(region_id, region_base_addr)`

### `Reverse(*args)`

### `RotateLeft(*args)`

### `RotateRight(*args)`

### `SDiv(*args)`

### `SMod(*args)`

### `SignExt(*args)`

### `SimplificationAvoidanceAnnotation`

Bases: `Annotation`

SimplificationAvoidanceAnnotation is an annotation that prevents simplification of an AST.

#### `eliminatable`

Returns whether this annotation can be eliminated in a simplification.

**Returns:**

True if eliminatable, False otherwise

#### `relocatable`

Returns whether this annotation can be relocated in a simplification.

**Returns:**

True if it can be relocated, false otherwise.

### `Solver`

Bases: `ConcreteHandlerMixin`, `EagerResolutionMixin`, `ConstraintFilterMixin`, `ConstraintDeduplicatorMixin`, `SimplifySkipperMixin`, `SatCacheMixin`, `ModelCacheMixin`, `ConstraintExpansionMixin`, `SimplifyHelperMixin`, `FullFrontend`

Solver is the default Claripy frontend. It uses Z3 as the backend solver by default.

#### `Solver.__init__(backend=<claripy.backends.backend_z3.BackendZ3 object>, **kwargs)`

### `SolverCacheless`

Bases: `ConcreteHandlerMixin`, `EagerResolutionMixin`, `ConstraintFilterMixin`, `ConstraintDeduplicatorMixin`, `SimplifySkipperMixin`, `FullFrontend`

SolverCacheless is a Solver without caching. It uses Z3 as the backend solver by default.

#### `SolverCacheless.__init__(backend=<claripy.backends.backend_z3.BackendZ3 object>, **kwargs)`

### `SolverComposite`

Bases: `ConcreteHandlerMixin`, `EagerResolutionMixin`, `ConstraintFilterMixin`, `ConstraintDeduplicatorMixin`, `SatCacheMixin`, `SimplifySkipperMixin`, `SimplifyHelperMixin`, `ConstraintExpansionMixin`, `CompositedCacheMixin`, `CompositeFrontend`

SolverComposite is a frontend that composes multiple templated frontends.

#### `SolverComposite.__init__(template_solver=None, track=False, **kwargs)`

### `SolverConcrete`

Bases: `ConcreteHandlerMixin`, `ConstraintFilterMixin`, `LightFrontend`

SolverConcrete is a thin frontend to the Concrete backend solver.

#### `SolverConcrete.__init__(**kwargs)`

### `SolverHybrid`

Bases: `ConcreteHandlerMixin`, `EagerResolutionMixin`, `ConstraintFilterMixin`, `ConstraintDeduplicatorMixin`, `SimplifySkipperMixin`, `HybridFrontend`

SolverHybrid is a frontend that uses an exact solver and an approximate solver.

#### `SolverHybrid.__init__(exact_frontend=None, approximate_frontend=None, complex_auto_replace=True, replace_constraints=True, track=False, approximate_first=False, **kwargs)`

### `SolverReplacement`

Bases: `ConcreteHandlerMixin`, `ConstraintDeduplicatorMixin`, `ReplacementFrontend`

SolverReplacement is a frontend wrapper that replaces constraints with their solutions.

#### `SolverReplacement.__init__(actual_frontend=None, **kwargs)`

### `SolverStrings`

Bases: `ConcreteHandlerMixin`, `ConstraintFilterMixin`, `ConstraintDeduplicatorMixin`, `EagerResolutionMixin`, `FullFrontend`

SolverStrings is a frontend that uses Z3 to solve string constraints.

#### `SolverStrings.__init__(*args, backend=<claripy.backends.backend_z3.BackendZ3 object>, **kwargs)`

### `SolverVSA`

Bases: `ConcreteHandlerMixin`, `ConstraintFilterMixin`, `LightFrontend`

SolverVSA is a thin frontend to the VSA backend solver.

#### `SolverVSA.__init__(**kwargs)`

### `StrConcat(*args)`

### `StrContains(*args)`

### `StrIndexOf(*args)`

### `StrIsDigit(*args)`

### `StrLen(*args)`

### `StrPrefixOf(*args)`

### `StrReplace(*args)`

### `StrSubstr(*args)`

### `StrSuffixOf(*args)`

### `StrToInt(*args)`

### `StringS(name, explicit_name=False, **kwargs)`

Create a new symbolic string (analogous to z3.String())

**Parameters:**

- **name** – The name of the symbolic string (i. e. the name of the variable)

- **explicit_name** (*bool*) – If False, an identifier is appended to the name to ensure uniqueness.

**Returns:**

The String object representing the symbolic string

### `StringV(value, **kwargs)`

Create a new Concrete string (analogous to z3.StringVal())

**Parameters:**

**value** – The constant value of the concrete string

**Returns:**

The String object representing the concrete string

### `UninitializedAnnotation`

Bases: `Annotation`

Use UninitializedAnnotation to annotate ASTs that are uninitialized.

#### `eliminatable: eliminatable = False`

#### `relocatable: relocatable = True`

### `UnsatError`

Bases: `ClaripyError`

### `ValueSet(bits, region, region_base_addr, value)`

**Parameters:**

- **bits** (*int*)

- **region** (*str*)

- **region_base_addr** (*int*)

- **value** (*BV** | **int*)

### `ZeroExt(*args)`

### `burrow_ite(expr)`

Returns an equivalent AST that “burrows” the ITE expressions as deep as possible into the ast, for simpler printing.

**Return type:**

`TypeVar`(`T`, bound= `Base`)

**Parameters:**

**expr** (*T*)

### `constraint_to_si(expr)`

Convert a constraint to SI if possible.

**Parameters:**

**expr**

**Returns:**

### `excavate_ite(expr)`

Returns an equivalent AST that “excavates” the ITE expressions out as far as possible toward the root of the AST, for processing in static analyses.

**Return type:**

`TypeVar`(`T`, bound= `Base`)

**Parameters:**

**expr** (*T*)

### `false()`

### `fpAbs(*args)`

### `fpAdd(*args)`

### `fpDiv(*args)`

### `fpEQ(*args)`

### `fpFP(*args)`

### `fpGEQ(*args)`

### `fpGT(*args)`

### `fpIsInf(*args)`

### `fpIsNaN(*args)`

### `fpLEQ(*args)`

### `fpLT(*args)`

### `fpMul(*args)`

### `fpNEQ(*args)`

### `fpNeg(*args)`

### `fpSqrt(*args)`

### `fpSub(*args)`

### `fpToFP(*args)`

### `fpToFPUnsigned(*args)`

### `fpToIEEEBV(*args)`

### `fpToSBV(*args)`

### `fpToUBV(*args)`

### `intersection(*args)`

### `is_false(expr)`

Checks if a boolean expression is trivially False.

A false result does not necessarily mean that the expression is False, but rather that it is not trivially False.

**Return type:**

`bool`

**Parameters:**

**expr** (*Bool*)

### `is_true(expr)`

Checks if a boolean expression is trivially True.

A false result does not necessarily mean that the expression is False, but rather that it is not trivially True.

**Return type:**

`bool`

**Parameters:**

**expr** (*Bool*)

### `ite_cases(cases, default)`

Return an expression of if-then-else trees which expresses a series of alternatives

**Parameters:**

- **cases** – A list of tuples (c, v). c is the condition under which v should be the result of the expression

- **default** – A default value that the expression should take on if none of the c conditions are satisfied

**Returns:**

An expression encoding the result of the above

### `ite_dict(i, d, default)`

Return an expression of if-then-else trees which expresses a switch tree :type i: :param i: The variable which may take on multiple values affecting the final result :type d: :param d: A dict mapping possible values for i to values which the result could be :type default: :param default: A default value that the expression should take on if i matches none of the keys of d :return: An expression encoding the result of the above

### `replace(expr, old, new)`

Returns this AST but with the AST ‘old’ replaced with AST ‘new’ in its subexpressions.

**Return type:**

`Base`

**Parameters:**

- **expr** (*Base*)

- **old** (*T*)

- **new** (*T*)

### `replace_dict(expr, replacements, variable_set=None, leaf_operation=<function <lambda>>)`

Returns this AST with subexpressions replaced by those that can be found in replacements dict.

**Parameters:**

- **variable_set** (`set`[`str`] | `None`) – For optimization, ast’s without these variables are not checked for replacing.

- **replacements** (`dict`[`int`, `Base`]) – A dictionary of hashes to their replacements.

- **leaf_operation** (`Callable`[[`Base`], `Base`]) – An operation that should be applied to the leaf nodes.

- **expr** (*Base*)

**Return type:**

`Base`

**Returns:**

An AST with all instances of ast’s in replacements.

### `reverse_ite_cases(ast)`

Given an expression created by ite_cases, produce the cases that generated it :type ast: :param ast: :return:

### `set_debug(enabled)`

Enable or disable the debug mode. In debug mode, a bunch of extra checks in claripy will be executed. You’ll want to disable debug mode if you are running performance critical code.

### `simplify(expr)`

Simplify an expression.

**Return type:**

`TypeVar`(`T`, bound= `Base`)

**Parameters:**

**expr** (*T*)

### `true()`

### `union(*args)`

### `widen(*args)`

### `ClaripyError`

Bases: `Exception`

### `UnsatError`

Bases: `ClaripyError`

### `ClaripyFrontendError`

Bases: `ClaripyError`

### `ClaripySerializationError`

Bases: `ClaripyError`

### `BackendError`

Bases: `ClaripyError`

### `BackendUnsupportedError`

Bases: `BackendError`

### `ClaripyZ3Error`

Bases: `ClaripyError`

### `ClaripyBackendVSAError`

Bases: `BackendError`

### `MissingSolverError`

Bases: `ClaripyError`

### `ClaripySolverInterruptError`

Bases: `ClaripyError`

### `ClaripyASTError`

Bases: `ClaripyError`

### `ClaripyBalancerError`

Bases: `ClaripyASTError`

### `ClaripyBalancerUnsatError`

Bases: `ClaripyBalancerError`

### `ClaripyTypeError`

Bases: `ClaripyASTError`

### `ClaripyValueError`

Bases: `ClaripyASTError`

### `ClaripySizeError`

Bases: `ClaripyASTError`

### `ClaripyOperationError`

Bases: `ClaripyASTError`

### `ClaripyReplacementError`

Bases: `ClaripyASTError`

### `ClaripyRecursionError`

Bases: `ClaripyOperationError`

### `ClaripyZeroDivisionError`

Bases: `ClaripyOperationError`, `ZeroDivisionError`

### `RM`

Bases: `Enum`

Rounding modes for floating point operations.

See https://en.wikipedia.org/wiki/IEEE_754#Rounding_rules for more information.

#### `RM_NearestTiesEven: RM_NearestTiesEven = 'RM_RNE'`

#### `RM_NearestTiesAwayFromZero: RM_NearestTiesAwayFromZero = 'RM_RNA'`

#### `RM_TowardsZero: RM_TowardsZero = 'RM_RTZ'`

#### `RM_TowardsPositiveInf: RM_TowardsPositiveInf = 'RM_RTP'`

#### `RM_TowardsNegativeInf: RM_TowardsNegativeInf = 'RM_RTN'`

#### `RM.default()`

#### `RM.pydecimal_equivalent_rounding_mode()`

### `FSort`

Bases: `object`

A class representing a floating point sort.

#### `FSort.__init__(name, exp, mantissa)`

#### `length`

#### `FSort.from_size(n)`

#### `FSort.from_params(exp, mantissa)`

### `op(name, arg_types, return_type, extra_check=None, calc_length=None)`

**Return type:**

`Callable`[`...`, `TypeVar`(`T`, bound= `Base`)]

**Parameters:**

**return_type** (*type**[**T**]*)

### `reversed_op(op_func)`

### `length_same_check(*args)`

### `basic_length_calc(*args)`

### `extract_check(high, low, bv)`

### `extend_check(amount, _)`

### `concat_length_calc(*args)`

### `extract_length_calc(high, low, _)`

### `ext_length_calc(ext, orig)`

### `if_simplifier(cond, if_true, if_false)`

### `concat_simplifier(*args)`

### `rshift_simplifier(val, shift)`

### `lshr_simplifier(val, shift)`

### `lshift_simplifier(val, shift)`

### `eq_simplifier(a, b)`

### `ne_simplifier(a, b)`

### `ge_simplifier(a, b)`

### `bv_reverse_simplifier(body)`

### `boolean_and_simplifier(*args)`

### `boolean_or_simplifier(*args)`

### `bitwise_add_simplifier(*args)`

### `bitwise_mul_simplifier(*args)`

### `bitwise_sub_simplifier(a, b)`

### `bitwise_xor_simplifier_minmax(a, b)`

### `bitwise_xor_simplifier(a, b, *args)`

### `bitwise_or_simplifier(a, b, *args)`

### `bitwise_and_simplifier(a, b, *args)`

### `boolean_not_simplifier(body)`

### `zeroext_simplifier(n, e)`

### `signext_simplifier(n, e)`

### `extract_simplifier(high, low, val)`

### `fptobv_simplifier(the_fp)`

### `fptofp_simplifier(*args)`

### `rotate_shift_mask_simplifier(a, b)`

**Handles the following case:**

**((A << a) | (A >> (_N - a))) & mask, where**

A being a BVS, a being a integer that is less than _N, _N is either 32 or 64, and mask can be evaluated to 0xffffffff (64-bit) or 0xffff (32-bit) after reversing the rotate-shift operation.

**It will be simplified to:**

: (A & (mask >>> a)) <<< a

### `str_reverse_simplifier(arg)`

### `invert_simplifier(expr)`

### `and_mask_comparing_against_constant_simplifier(op, a, b)`

This simplifier handles the following case:

> A & mask == b, and A & mask != b

If the high bits of A are 0, & mask can be eliminated.

### `zeroext_extract_comparing_against_constant_simplifier(op, a, b)`

This simplifier handles the following cases:

> Extract(hi, 0, Concat(0, A)) op b, and Extract(hi, 0, ZeroExt(n, A)) op b

Extract can be eliminated if the high bits of Concat(0, A) or ZeroExt(n, A) are all zeros.

### `zeroext_comparing_against_simplifier(op, a, b)`

This simplifier handles the following cases:

> ZeroExt(n, A) == b, ZeroExt(n, A) != b, and ZeroExt(n, A) >= b

If the high bits of b are all zeros (in case of ==, !=, and >=) or have at leclaripy one ones (in case of !=), ZeroExt can be eliminated.

### `simplify(op, args)`

Simplifies the given operation with the given arguments. Returns the simplified result if possible, along with a boolean representing whether annotations were handled by the simplifier.

**Return type:**

`tuple`[`Base` | `None`, `bool`]

### `set_debug(enabled)`

Enable or disable the debug mode. In debug mode, a bunch of extra checks in claripy will be executed. You’ll want to disable debug mode if you are running performance critical code.

---

## claripy 快速上手

Claripy is an abstracted constraint-solving wrapper.

## Project Links

Project repository: https://github.com/angr/claripy

Documentation: https://api.angr.io/projects/claripy/en/latest/

## Usage

It is usable!

General usage is similar to Z3:

```
>>> import claripy
>>> a = claripy.BVV(3, 32)
>>> b = claripy.BVS('var_b', 32)
>>> s = claripy.Solver()
>>> s.add(b > a)
>>> print(s.eval(b, 1)[0])

```

---

