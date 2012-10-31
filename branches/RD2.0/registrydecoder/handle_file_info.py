
class rfileinfo:
    def __init__(self, evidence_file, alias, reg_file, reg_type, hashvalue, mtime, group_name, part_num, type_name, rpname=""):
        self.evidence_file = evidence_file
        self.alias         = alias
        self.reg_file      = reg_file
        self.reg_type      = reg_type
        self.hashvalue     = hashvalue
        self.mtime         = mtime
        self.group_name    = group_name
        self.part_num      = part_num
        self.type_name     = type_name
        self.rp_name       = rpname

# tree displayed of registry files to be analyzed
class tree_entry:
    def __init__(self, name):
        # all the file ids in the tree
        self.fileids = []
        self.subs  = []
        self.name    = name

def get_hives_info(gui):
    # do not change the order of these!
    (fileinfo_hash, root) = _handle_images(gui)

    (fileinfo_hash, root) = _handle_single(gui, fileinfo_hash, root)

    return (fileinfo_hash, root)

def _get_ename(efile, alias):
    if alias:
        ename = alias
    else:
        ename = efile

    return ename

def _handle_single(gui, fileinfo_hash, root):
    cursor = gui.case_obj.evidencedb.cursor 

    cursor.execute("select g.id, e.filename, e.file_alias from file_groups as g, evidence_sources as e where g.group_name='SINGLE' and e.id=g.partition_id")

    for (gid, evidence_file, alias) in cursor.fetchall():

        cursor.execute("select id, registry_type, md5sum, mtime from registry_files where hive_type=-1 and reg_type_id=?", [gid])
    
        for (efileid, rtype, md5sum, mtime) in cursor.fetchall():

            ename = _get_ename(evidence_file, alias)
            efile = tree_entry(ename)
            root.subs.append(efile)
            efile.fileids.append(efileid)            
            root.fileids.append(efileid)

            fileinfo_hash[efileid] = rfileinfo(evidence_file, ename, evidence_file, rtype, md5sum, mtime, "SINGLE", -1, "SINGLE_TYPE") 

    return (fileinfo_hash, root)

def _handle_images(gui):
    fileinfo_hash = {}

    # hash kept to make display code sane
    root = tree_entry("All Files")

    cursor = gui.case_obj.evidencedb.cursor
    cursor.execute("select filename, file_alias, id from evidence_sources")

    files  = cursor.fetchall()
    
    # for every evidence file
    for (evidence_file, alias, efileid) in files:
        ename = _get_ename(evidence_file, alias)

        cursor.execute("select number, id from partitions where evidence_file_id=?", [efileid]) 
        partitions = cursor.fetchall()
   
        # individual registry files
        if len(partitions) == 0:
            continue

        efile = tree_entry(ename)
        root.subs.append(efile)
        
        # for each partition in the current evidence file         
        for (part_num, part_id) in partitions:

            part = tree_entry("Partition %d" % part_num)
            efile.subs.append(part)
       
            cursor.execute("select group_name, id from file_groups where partition_id=?", [part_id])
            groups = cursor.fetchall()

            # for each group in the parition 
            for (group_name, gid) in groups:

                if group_name == "SINGLE":
                    continue

                gent = tree_entry(group_name)
                part.subs.append(gent)

                cursor.execute("select type_name, id from reg_type where file_group_id=?", [gid])
                reg_types = cursor.fetchall()

                for (type_name, type_id) in reg_types:

                    tent = tree_entry(type_name)
                    gent.subs.append(tent) 

                    # check if this is an RP directory
                    cursor.execute("select rpname, id from rp_groups where reg_type_id=?", [type_id])
                    rps = cursor.fetchall()

                    tree_ents = [root, efile, part, gent, tent]

                    # this is an RP folder
                    if len(rps) > 0:
                    
                        for (rpname, rp_id) in rps: 
                            
                            rent = tree_entry(rpname)
                            tent.subs.append(rent)

                            cursor.execute("select filename, id, registry_type, md5sum, mtime from registry_files where reg_type_id=? and hive_type=1", [rp_id])

                            _populate_file(evidence_file, ename, fileinfo_hash, cursor, rent, tree_ents + [rent], group_name, part_num, type_name, rpname)

                    # non-RP
                    else:
                        # get all the files from a group
                        cursor.execute("select filename, id, registry_type, md5sum, mtime from registry_files where reg_type_id=? and hive_type=0", [type_id])

                        _populate_file(evidence_file, ename, fileinfo_hash, cursor, tent, tree_ents, group_name, part_num, type_name)

    return (fileinfo_hash, root)

def _populate_file(evidence_file, ename, fileinfo_hash, cursor, ent, tree_ents, group_name, part_num, type_name, rpname=""):
 
    regfiles = cursor.fetchall()

    for (rfile, fileid, rtype, md5sum, mtime) in regfiles:
        
        fent = tree_entry(rfile)
        ent.subs.append(fent)

        fileinfo_hash[fileid] = rfileinfo(evidence_file, ename, rfile, rtype, md5sum, mtime, group_name, part_num, type_name, rpname) 

        for ent in tree_ents:
            ent.fileids.append(fileid)

        fent.fileids.append(fileid)


