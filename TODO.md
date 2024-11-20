# TODO

- [x] Change protobuf API
- [x] Add `load` and `attach` commands to the CLI
- [x] Implement the `load` command
- [x] Implement the `attach` command
- [x] Split the `load` and `attach` logic in bpfman core
- [ ] Fix the code for writing/reading links into the database
- [ ] Ensure that we pin links to a new `links` directory in bpffs
    - [ ] Check link retrieval code + libxdp compatibility
- [ ] Finish implementing the multi-attach load/attach split
    - [ ] Ensure we have a persistent "dummy" dispatcher available for load
    - [ ] Finishing migrating the old "load" logic to "attach"
- [ ] Adjust `list` logic to display a list of links
- [ ] Check the CLI interface makes sense post load/attach split
  - [ ] Document the new CLI interface
  - [ ] Open issues for the rough edges (i.e having to specify `program_type:name`)
  - [ ] Plan work in Aya to address
- [ ] Update e2e tests
- [ ] Manual Testing
